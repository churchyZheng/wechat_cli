#!/usr/bin/env python3
import argparse
import json
import os
import pathlib
import queue
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import frida


ROOT_DIR = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_SCRIPT_PATH = ROOT_DIR / "frida" / "succ.js"
DEFAULT_RECEIVER_SCRIPT_PATH = ROOT_DIR / "frida" / "receiver.js"
DEFAULT_DAEMON_ADDR = "127.0.0.1:58280"
CLOSE_TIMEOUT_SECONDS = 2.0
MEDIA_IDLE_SECONDS = 1.0
MEDIA_WAIT_TIMEOUT_SECONDS = 8.0
NATIVE_FILE_WAIT_TIMEOUT_SECONDS = 12.0
MEDIA_RESOLVE_TIMEOUT_SECONDS = (MEDIA_WAIT_TIMEOUT_SECONDS * 2) + NATIVE_FILE_WAIT_TIMEOUT_SECONDS
SCRIPT_LOAD_TIMEOUT_SECONDS = 15.0
RUNTIME_HELPER_JS = r"""
;(function () {
    const __origExports = rpc.exports || {};
    rpc.exports = Object.assign({}, __origExports, {
        getDaemonStatus() {
            return {
                templateReady: typeof textTemplateReady !== "undefined" ? !!textTemplateReady : false,
                capturedTextTaskId: typeof capturedTextTaskId !== "undefined" ? capturedTextTaskId : 0,
                triggerX0: (typeof triggerX0 !== "undefined" && triggerX0) ? triggerX0.toString() : "",
                triggerX1Payload: (typeof triggerX1Payload !== "undefined" && triggerX1Payload) ? triggerX1Payload.toString() : "",
                sendMsgType: typeof sendMsgType !== "undefined" && sendMsgType ? String(sendMsgType) : ""
            };
        },
        cleanupForDetach() {
            try {
                if (typeof restoreOriginalInstruction === "function") {
                    if (typeof patchTextProtobufAddr !== "undefined" && typeof patchTextProtobufByte !== "undefined" && patchTextProtobufByte !== null) {
                        restoreOriginalInstruction(patchTextProtobufAddr, patchTextProtobufByte);
                    }
                    if (typeof patchTextProtobufDeleteAddr !== "undefined" && typeof patchTextProtobufDeleteByte !== "undefined" && patchTextProtobufDeleteByte !== null) {
                        restoreOriginalInstruction(patchTextProtobufDeleteAddr, patchTextProtobufDeleteByte);
                    }
                }

                if (typeof insertMsgAddr !== "undefined" && insertMsgAddr && !insertMsgAddr.isNull()) {
                    try {
                        insertMsgAddr.writeU64(0);
                    } catch (_) {}
                    insertMsgAddr = ptr(0);
                }

                if (typeof clearTextSendState === "function") {
                    clearTextSendState();
                }

                return { ok: true };
            } catch (e) {
                return { ok: false, error: String(e) };
            }
        }
    });
})();
"""


class SendContext:
    def __init__(self, verbose: bool) -> None:
        self.verbose = verbose
        self.template_ready = threading.Event()
        self.send_finished = threading.Event()
        self.session_detached = threading.Event()
        self.incoming_messages = queue.Queue()
        self.script_error = None
        self.detach_reason = None
        self.download_lock = threading.Lock()
        self.downloads_by_cdn = {}

    def enrich_incoming_message(self, payload: dict) -> dict:
        if not isinstance(payload, dict):
            return payload

        enriched = dict(payload)
        message_type = enriched.get("message_type")
        sender = enriched.get("sender") or {}
        user_id = enriched.get("user_id") or ""
        group_id = enriched.get("group_id") or ""
        sender_user_id = sender.get("user_id") or user_id

        if message_type == "group" and group_id:
            enriched["send_target"] = group_id
            enriched["send_target_source"] = "group_id"
        elif sender_user_id:
            enriched["send_target"] = sender_user_id
            enriched["send_target_source"] = "sender.user_id"
        elif user_id:
            enriched["send_target"] = user_id
            enriched["send_target_source"] = "user_id"

        return enriched

    def on_message(self, message, data) -> None:
        msg_type = message.get("type")

        if msg_type == "log":
            payload = message.get("payload", "")
            if self.verbose and payload:
                print(f"[js] {payload}", file=sys.stderr)
            return

        if msg_type == "send":
            payload = message.get("payload") or {}
            if isinstance(payload, dict) and payload.get("type") == "finish":
                self.send_finished.set()
                if self.verbose:
                    print("[js] 收到 finish", file=sys.stderr)
                return
            if isinstance(payload, dict) and payload.get("type") == "download":
                self.record_download(payload)
                if self.verbose:
                    print(f"[js] 收到下载分片: {json.dumps(payload, ensure_ascii=False)}", file=sys.stderr)
                return
            if isinstance(payload, dict) and payload.get("type") == "send" and "message_type" in payload:
                self.incoming_messages.put(self.enrich_incoming_message(payload))
                if self.verbose:
                    print(f"[js] 收到消息: {json.dumps(payload, ensure_ascii=False)}", file=sys.stderr)
            return

        if msg_type == "error":
            description = message.get("description") or "unknown script error"
            self.script_error = RuntimeError(description)
            return

    def on_detached(self, reason, crash) -> None:
        self.detach_reason = f"session detached: {reason}"
        self.session_detached.set()

    def record_download(self, payload: dict) -> None:
        cdn_url = payload.get("cdn_url") or ""
        media = payload.get("media") or []
        if not cdn_url or not isinstance(media, list):
            return

        try:
            chunk = bytes(int(item) & 0xFF for item in media)
        except Exception:
            return

        now = time.time()
        with self.download_lock:
            entry = self.downloads_by_cdn.get(cdn_url)
            if entry is None:
                entry = {
                    "file_id": payload.get("file_id", ""),
                    "media": bytearray(),
                    "last_append_time": 0.0,
                    "file_path": "",
                    "download_requested": False,
                }
                self.downloads_by_cdn[cdn_url] = entry

            if payload.get("file_id"):
                entry["file_id"] = payload["file_id"]
            if chunk:
                entry["media"].extend(chunk)
            entry["last_append_time"] = now

    def get_download_file_path(self, cdn_url: str) -> str:
        with self.download_lock:
            entry = self.downloads_by_cdn.get(cdn_url)
            if not entry:
                return ""
            return entry.get("file_path", "")

    def set_download_file_path(self, cdn_url: str, file_path: str) -> None:
        with self.download_lock:
            entry = self.downloads_by_cdn.get(cdn_url)
            if entry is None:
                entry = {"file_id": "", "media": bytearray(), "last_append_time": 0.0, "file_path": "", "download_requested": False}
                self.downloads_by_cdn[cdn_url] = entry
            entry["file_path"] = file_path
            entry["media"] = bytearray()

    def mark_download_requested(self, cdn_url: str) -> bool:
        with self.download_lock:
            entry = self.downloads_by_cdn.get(cdn_url)
            if entry is None:
                entry = {
                    "file_id": "",
                    "media": bytearray(),
                    "last_append_time": 0.0,
                    "file_path": "",
                    "download_requested": False,
                }
                self.downloads_by_cdn[cdn_url] = entry
            if entry.get("download_requested"):
                return False
            entry["download_requested"] = True
            return True

    def reset_download_requested(self, cdn_url: str) -> None:
        with self.download_lock:
            entry = self.downloads_by_cdn.get(cdn_url)
            if not entry:
                return
            entry["download_requested"] = False

    def wait_for_download_media(self, cdn_url: str, timeout_seconds: float, idle_seconds: float = MEDIA_IDLE_SECONDS) -> bytes:
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            with self.download_lock:
                entry = self.downloads_by_cdn.get(cdn_url)
                if entry and entry.get("file_path"):
                    return b""
                if entry and entry["media"] and time.time() - entry.get("last_append_time", 0.0) >= idle_seconds:
                    return bytes(entry["media"])
            time.sleep(0.2)
        return b""


def wait_for_event(ctx: SendContext, event: threading.Event, timeout_seconds: float, purpose: str) -> None:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        if event.wait(timeout=0.2):
            return
        if ctx.script_error is not None:
            raise ctx.script_error
        if ctx.session_detached.is_set():
            raise RuntimeError(ctx.detach_reason or "session detached")
    raise TimeoutError(purpose)


def attach_gadget(gadget_addr: str):
    manager = frida.get_device_manager()
    device = manager.add_remote_device(gadget_addr)
    session = device.attach("Gadget")
    return session


def load_script(session, script_path: pathlib.Path, ctx: SendContext, helper_js: str = ""):
    code = script_path.read_text(encoding="utf-8")
    if helper_js:
        code += "\n" + helper_js
    result = {"script": None, "error": None}

    def do_load() -> None:
        try:
            script = session.create_script(code)
            script.on("message", ctx.on_message)
            script.load()
            result["script"] = script
        except Exception as exc:
            result["error"] = exc

    load_thread = threading.Thread(target=do_load, daemon=True)
    load_thread.start()
    load_thread.join(SCRIPT_LOAD_TIMEOUT_SECONDS)

    if load_thread.is_alive():
        best_effort_close([result.get("script")], session, CLOSE_TIMEOUT_SECONDS)
        raise TimeoutError(f"加载脚本超时: {script_path.name}")

    if result["error"] is not None:
        raise result["error"]

    return result["script"]


def parse_task_id(raw_task_id: str) -> int:
    try:
        return int(raw_task_id, 0)
    except ValueError as exc:
        raise SystemExit(f"无效的 task id: {raw_task_id}") from exc


def parse_host_port(raw_addr: str) -> tuple[str, int]:
    host, sep, port_text = raw_addr.rpartition(":")
    if not sep or not host or not port_text:
        raise SystemExit(f"无效地址: {raw_addr}")
    try:
        return host, int(port_text)
    except ValueError as exc:
        raise SystemExit(f"无效端口: {raw_addr}") from exc


def post_json(daemon_addr: str, path: str, payload: dict) -> dict:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        f"http://{daemon_addr}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=payload.get("client_timeout", 30)) as response:
            body = response.read().decode("utf-8")
            return json.loads(body)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8") or exc.reason
        raise SystemExit(f"daemon 请求失败: HTTP {exc.code} {body}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"无法连接 daemon: {exc.reason}") from exc


def get_json(daemon_addr: str, path: str) -> dict:
    request = urllib.request.Request(f"http://{daemon_addr}{path}", method="GET")
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8") or exc.reason
        raise SystemExit(f"daemon 请求失败: HTTP {exc.code} {body}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"无法连接 daemon: {exc.reason}") from exc


def format_incoming_message(message: dict) -> dict:
    if not isinstance(message, dict):
        return {"message": message}

    sender = message.get("sender") or {}
    segments = message.get("message") or []
    message_types = []
    text_parts = []

    for segment in segments:
        if not isinstance(segment, dict):
            continue
        seg_type = segment.get("type")
        if seg_type:
            message_types.append(seg_type)
        data = segment.get("data") or {}
        if seg_type == "text" and isinstance(data, dict):
            text = data.get("text")
            if text:
                text_parts.append(text)

    formatted = {
        "time": message.get("time"),
        "message_type": message.get("message_type"),
        "send_target": message.get("send_target", ""),
        "from_user_id": sender.get("user_id") or message.get("user_id", ""),
        "from_nickname": sender.get("nickname") or "",
        "self_id": message.get("self_id", ""),
        "group_id": message.get("group_id", ""),
        "message_id": message.get("message_id", ""),
        "message_types": message_types,
        "text": "".join(text_parts),
        "raw_message": message.get("raw_message", ""),
    }

    show_content = message.get("show_content")
    if show_content:
        formatted["show_content"] = show_content

    if message.get("image_path"):
        formatted["image_path"] = message["image_path"]
    if message.get("file_path"):
        formatted["file_path"] = message["file_path"]
    if message.get("file_url"):
        formatted["file_url"] = message["file_url"]

    return formatted


def render_incoming_message_text(message: dict) -> str:
    message_types = message.get("message_types") or []
    if isinstance(message_types, list):
        message_types_text = "/".join(str(item) for item in message_types if item)
    else:
        message_types_text = str(message_types or "")

    lines = [
        f"- send_target: {message.get('send_target', '')}",
        f"- from_user_id: {message.get('from_user_id', '')}",
        f"- from_nickname: {message.get('from_nickname', '')}",
        f"- self_id: {message.get('self_id', '')}",
        f"- group_id: {message.get('group_id', '')}",
        f"- message_type: {message.get('message_type', '')}",
        f"- message_id: {message.get('message_id', '')}",
        f"- message_types: {message_types_text}",
        f"- text: {message.get('text', '')}",
        f"- raw_message: {message.get('raw_message', '')}",
    ]
    if message.get("image_path"):
        lines.append(f"- image_path: {message.get('image_path', '')}")
    if message.get("file_path"):
        lines.append(f"- file_path: {message.get('file_path', '')}")
    if message.get("file_url"):
        lines.append(f"- file_url: {message.get('file_url', '')}")
    return "\n".join(lines)


def detect_file_format(data: bytes) -> str:
    if len(data) < 8:
        return "unknown"
    if data.startswith(b"\xFF\xD8\xFF"):
        return "jpg"
    if data.startswith(b"\x89PNG\r\n\x1A\n"):
        return "png"
    if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return "gif"
    if data.startswith(b"BM"):
        return "bmp"
    if data.startswith(b"RIFF") and len(data) > 12 and data[8:12] == b"WEBP":
        return "webp"
    return "unknown"


def save_media_file(ext: str, data: bytes, category: str | None = None) -> str:
    if category is None:
        category = "image" if ext in {"jpg", "png", "gif", "bmp", "webp"} else "file"
    target_dir = ROOT_DIR / category
    target_dir.mkdir(parents=True, exist_ok=True)
    filename = f"{time.time_ns()}_{os.getpid()}.{ext}"
    target_path = target_dir / filename
    target_path.write_bytes(data)
    return str(target_path)


def copy_media_file(source_path: str, category: str = "file", preferred_name: str = "") -> str:
    source = pathlib.Path(source_path)
    if not source.exists() or not source.is_file():
        return ""

    target_dir = ROOT_DIR / category
    target_dir.mkdir(parents=True, exist_ok=True)

    source_size = 0
    try:
        source_size = source.stat().st_size
    except OSError:
        pass

    base_name = os.path.basename(preferred_name) if preferred_name else source.name
    if not base_name:
        base_name = source.name

    stem = pathlib.Path(base_name).stem or f"file_{time.time_ns()}"
    suffix = pathlib.Path(base_name).suffix
    target_path = target_dir / base_name

    if target_path.exists():
        try:
            if target_path.stat().st_size == source_size and source_size > 0:
                return str(target_path)
        except OSError:
            pass

        index = 1
        while True:
            candidate = target_dir / f"{stem}({index}){suffix}"
            if not candidate.exists():
                target_path = candidate
                break
            try:
                if candidate.stat().st_size == source_size and source_size > 0:
                    return str(candidate)
            except OSError:
                pass
            index += 1

    shutil.copy2(source, target_path)
    return str(target_path)


def decrypt_wechat_media(data: bytes, aes_key_hex: str) -> bytes:
    if not data or not aes_key_hex or len(data) % 16 != 0:
        return b""
    try:
        result = subprocess.run(
            [
                "openssl",
                "enc",
                "-d",
                "-aes-128-ecb",
                "-nopad",
                "-nosalt",
                "-K",
                aes_key_hex,
            ],
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return b""
    return result.stdout


def best_effort_close(scripts, session, timeout_seconds: float = CLOSE_TIMEOUT_SECONDS) -> bool:
    def cleanup() -> None:
        for script in scripts:
            if script is not None:
                try:
                    script.unload()
                except Exception:
                    pass
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass

    cleanup_thread = threading.Thread(target=cleanup, daemon=True)
    cleanup_thread.start()
    cleanup_thread.join(timeout_seconds)
    return not cleanup_thread.is_alive()


class WeChatRuntime:
    def __init__(
        self,
        gadget_addr: str,
        script_path: pathlib.Path,
        receiver_script_path: pathlib.Path,
        verbose: bool,
        send_timeout: float,
    ) -> None:
        self.gadget_addr = gadget_addr
        self.script_path = script_path
        self.receiver_script_path = receiver_script_path
        self.verbose = verbose
        self.send_timeout = send_timeout
        self.send_ctx = SendContext(verbose=verbose)
        self.receive_ctx = SendContext(verbose=verbose)
        self.session = None
        self.script = None
        self.receiver_script = None
        self.task_id = 0x20000095
        self.task_lock = threading.Lock()
        self.send_lock = threading.Lock()

    def start(self) -> None:
        try:
            self.session = attach_gadget(self.gadget_addr)
            self.session.on("detached", self.on_detached)
            self.script = load_script(self.session, self.script_path, self.send_ctx, helper_js=RUNTIME_HELPER_JS)
            self.receiver_script = load_script(self.session, self.receiver_script_path, self.receive_ctx)
        except Exception:
            best_effort_close([self.receiver_script, self.script], self.session, CLOSE_TIMEOUT_SECONDS)
            self.session = None
            self.script = None
            self.receiver_script = None
            raise

    def on_detached(self, reason, crash) -> None:
        self.send_ctx.on_detached(reason, crash)
        self.receive_ctx.on_detached(reason, crash)

    def close(self, timeout_seconds: float = CLOSE_TIMEOUT_SECONDS) -> bool:
        if self.script is not None:
            try:
                self.script.exports_sync.cleanup_for_detach()
            except Exception:
                pass
        return best_effort_close([self.receiver_script, self.script], self.session, timeout_seconds)

    def next_task_id(self) -> int:
        with self.task_lock:
            current = self.task_id
            self.task_id += 1
            return current

    def ensure_alive(self) -> None:
        if self.send_ctx.script_error is not None:
            raise self.send_ctx.script_error
        if self.send_ctx.session_detached.is_set():
            raise RuntimeError(self.send_ctx.detach_reason or "session detached")

    def ensure_receiver_alive(self) -> None:
        if self.receive_ctx.script_error is not None:
            raise self.receive_ctx.script_error
        if self.receive_ctx.session_detached.is_set():
            raise RuntimeError(self.receive_ctx.detach_reason or "session detached")

    def fetch_daemon_status(self) -> dict:
        self.ensure_alive()
        status = self.script.exports_sync.get_daemon_status()
        if status.get("templateReady"):
            self.send_ctx.template_ready.set()
        return status

    def wait_for_template(self, timeout_seconds: float) -> dict:
        deadline = time.time() + timeout_seconds
        last_status = {}
        while time.time() < deadline:
            last_status = self.fetch_daemon_status()
            if last_status.get("templateReady"):
                return last_status
            time.sleep(0.2)
        raise TimeoutError("等待模板超时")

    def status(self) -> dict:
        self.ensure_alive()
        daemon_status = self.fetch_daemon_status()
        return {
            "attached": True,
            "template_ready": bool(daemon_status.get("templateReady")),
            "gadget_addr": self.gadget_addr,
            "script": str(self.script_path),
            "receiver_script": str(self.receiver_script_path),
            "captured_text_task_id": daemon_status.get("capturedTextTaskId", 0),
            "trigger_x0": daemon_status.get("triggerX0", ""),
            "trigger_x1_payload": daemon_status.get("triggerX1Payload", ""),
            "send_msg_type": daemon_status.get("sendMsgType", ""),
            "pending_messages": self.receive_ctx.incoming_messages.qsize(),
        }

    def send_text(self, target: str, content: str, at_user: str = "") -> dict:
        self.ensure_alive()
        status = self.fetch_daemon_status()
        if not status.get("templateReady"):
            raise RuntimeError("模板未就绪，请先在微信里手动发送一条普通文本消息")

        with self.send_lock:
            self.ensure_alive()
            task_id = self.next_task_id()
            self.send_ctx.send_finished.clear()
            result = self.script.exports_sync.trigger_send_text_message(task_id, target, content, at_user)
            if result != "ok":
                raise RuntimeError(f"triggerSendTextMessage 返回异常: {result}")
            wait_for_event(self.send_ctx, self.send_ctx.send_finished, self.send_timeout, "等待 finish 超时")
            return {
                "status": "ok",
                "task_id": task_id,
                "target": target,
                "message": content,
            }

    def enrich_media_message(self, message: dict) -> dict:
        if not isinstance(message, dict):
            return message

        segments = message.get("message") or []
        if not isinstance(segments, list):
            return message

        enriched = dict(message)
        enriched_segments = []

        for segment in segments:
            if not isinstance(segment, dict):
                enriched_segments.append(segment)
                continue

            segment_copy = dict(segment)
            data = dict(segment_copy.get("data") or {})
            segment_copy["data"] = data

            if segment_copy.get("type") == "image":
                file_path = self.resolve_image_path(data.get("text", ""))
                if file_path:
                    data["file_path"] = file_path
                    data["url"] = "file://" + file_path
                    enriched["image_path"] = file_path
                    enriched["file_url"] = "file://" + file_path
            elif segment_copy.get("type") == "file":
                file_path = self.resolve_file_path(
                    data.get("text", ""),
                    enriched.get("send_target", ""),
                    enriched.get("self_id", ""),
                )
                if file_path:
                    data["file_path"] = file_path
                    data["url"] = "file://" + file_path
                    enriched["file_path"] = file_path
                    enriched["file_url"] = "file://" + file_path

            enriched_segments.append(segment_copy)

        enriched["message"] = enriched_segments
        return enriched

    def resolve_image_path(self, raw_xml: str) -> str:
        if not raw_xml:
            return ""

        try:
            root = ET.fromstring(raw_xml)
        except ET.ParseError:
            return ""

        image_node = root.find(".//img")
        if image_node is None:
            return ""

        cdn_url = image_node.attrib.get("cdnmidimgurl") or image_node.attrib.get("cdnthumburl") or ""
        aes_key = image_node.attrib.get("aeskey") or image_node.attrib.get("cdnthumbaeskey") or ""
        if not cdn_url or not aes_key:
            return ""

        return self.resolve_downloaded_media_path(cdn_url, aes_key, category="image")

    def resolve_file_path(self, raw_xml: str, download_target: str, self_id: str = "") -> str:
        if not raw_xml:
            return ""

        try:
            root = ET.fromstring(raw_xml)
        except ET.ParseError:
            return ""

        attach_node = root.find(".//appmsg/appattach")
        if attach_node is None:
            return ""

        title = (root.findtext(".//appmsg/title") or "").strip()
        cdn_url = (attach_node.findtext("cdnattachurl") or "").strip()
        aes_key = (attach_node.findtext("aeskey") or "").strip()
        file_ext = (attach_node.findtext("fileext") or "").strip().lstrip(".")
        total_len = 0
        total_len_text = (attach_node.findtext("totallen") or "").strip()
        if total_len_text.isdigit():
            total_len = int(total_len_text)

        file_name = title or ""
        if file_name and "." not in pathlib.Path(file_name).name and file_ext:
            file_name = f"{file_name}.{file_ext}"

        existing_local_path = self.wait_for_wechat_local_file(file_name, total_len, self_id)
        if existing_local_path:
            copied_path = copy_media_file(existing_local_path, category="file", preferred_name=file_name)
            if copied_path and cdn_url:
                self.receive_ctx.set_download_file_path(cdn_url, copied_path)
            if copied_path:
                return copied_path

        return ""

    def iter_wechat_msg_file_roots(self, self_id: str = "") -> list[pathlib.Path]:
        xwechat_root = pathlib.Path.home() / "Library" / "Containers" / "com.tencent.xinWeChat" / "Data" / "Documents" / "xwechat_files"
        if not xwechat_root.exists():
            return []

        roots = []
        seen = set()

        if self_id:
            for candidate in xwechat_root.glob(f"{self_id}_*/msg/file"):
                if candidate.is_dir():
                    resolved = candidate.resolve()
                    if resolved not in seen:
                        seen.add(resolved)
                        roots.append(resolved)

        for candidate in xwechat_root.glob("*/msg/file"):
            if candidate.is_dir():
                resolved = candidate.resolve()
                if resolved not in seen:
                    seen.add(resolved)
                    roots.append(resolved)

        return roots

    def find_wechat_local_file(self, file_name: str, total_len: int = 0, self_id: str = "") -> str:
        if not file_name:
            return ""

        wanted_name = os.path.basename(file_name)
        wanted_suffix = pathlib.Path(wanted_name).suffix.lower()
        wanted_stem = pathlib.Path(wanted_name).stem
        candidates = []

        for root in self.iter_wechat_msg_file_roots(self_id):
            for candidate in root.rglob(wanted_name):
                if candidate.is_file():
                    candidates.append(candidate)
            if not candidates and wanted_suffix:
                pattern = f"{wanted_stem}*{wanted_suffix}"
                for candidate in root.rglob(pattern):
                    if candidate.is_file():
                        candidates.append(candidate)

        best_path = ""
        best_score = None
        for candidate in candidates:
            try:
                stat = candidate.stat()
            except OSError:
                continue

            score = 0
            if candidate.name == wanted_name:
                score += 10
            if wanted_suffix and candidate.suffix.lower() == wanted_suffix:
                score += 2
            if total_len > 0 and stat.st_size == total_len:
                score += 20

            rank = (score, stat.st_mtime)
            if best_score is None or rank > best_score:
                best_score = rank
                best_path = str(candidate)

        return best_path

    def wait_for_wechat_local_file(self, file_name: str, total_len: int = 0, self_id: str = "", timeout_seconds: float = NATIVE_FILE_WAIT_TIMEOUT_SECONDS) -> str:
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            found_path = self.find_wechat_local_file(file_name, total_len, self_id)
            if found_path:
                return found_path
            time.sleep(0.5)
        return ""

    def resolve_downloaded_media_path(
        self,
        cdn_url: str,
        aes_key: str,
        fallback_ext: str | None = None,
        category: str = "file",
        download_target: str = "",
        file_type: int = 0,
    ) -> str:
        existing_path = self.receive_ctx.get_download_file_path(cdn_url)
        if existing_path:
            return existing_path

        media = self.receive_ctx.wait_for_download_media(cdn_url, MEDIA_WAIT_TIMEOUT_SECONDS)
        if not media and category == "file":
            for candidate_type in self.iter_media_file_types(file_type):
                native_target_path = self.request_media_download(
                    download_target,
                    cdn_url,
                    aes_key,
                    fallback_ext or "bin",
                    candidate_type,
                )
                if native_target_path:
                    native_target_path = self.wait_for_native_file(native_target_path, NATIVE_FILE_WAIT_TIMEOUT_SECONDS)
                if native_target_path:
                    self.receive_ctx.set_download_file_path(cdn_url, native_target_path)
                    return native_target_path
            media = self.receive_ctx.wait_for_download_media(cdn_url, MEDIA_WAIT_TIMEOUT_SECONDS)
        if not media:
            if category == "file":
                self.receive_ctx.reset_download_requested(cdn_url)
            return ""

        decrypted = decrypt_wechat_media(media, aes_key)
        if not decrypted:
            return ""

        ext = detect_file_format(decrypted)
        if ext == "unknown":
            ext = (fallback_ext or "bin").lower()

        file_path = save_media_file(ext, decrypted, category=category)
        self.receive_ctx.set_download_file_path(cdn_url, file_path)
        return file_path

    def iter_media_file_types(self, preferred_type: int) -> list[int]:
        candidates = []
        if preferred_type > 0:
            candidates.append(preferred_type)
        for fallback_type in (7, 5):
            if fallback_type not in candidates:
                candidates.append(fallback_type)
        return candidates

    def wait_for_native_file(self, file_path: str, timeout_seconds: float) -> str:
        if not file_path:
            return ""

        deadline = time.time() + timeout_seconds
        last_size = -1
        stable_since = 0.0

        while time.time() < deadline:
            if os.path.exists(file_path):
                try:
                    size = os.path.getsize(file_path)
                except OSError:
                    size = 0
                if size > 0:
                    if size == last_size:
                        if stable_since == 0.0:
                            stable_since = time.time()
                        elif time.time() - stable_since >= 1.0:
                            return file_path
                    else:
                        last_size = size
                        stable_since = 0.0
            time.sleep(0.2)

        if os.path.exists(file_path):
            try:
                if os.path.getsize(file_path) > 0:
                    return file_path
            except OSError:
                return ""
        return ""

    def request_media_download(self, download_target: str, cdn_url: str, aes_key: str, file_ext: str, file_type: int) -> str:
        if not download_target or not cdn_url or not aes_key or file_type <= 0:
            return ""
        if not self.receive_ctx.mark_download_requested(cdn_url):
            return ""

        target_dir = ROOT_DIR / "file"
        target_dir.mkdir(parents=True, exist_ok=True)
        native_target_path = str(target_dir / f"native_{time.time_ns()}_{os.getpid()}.{(file_ext or 'bin').lower()}")

        try:
            result = self.receiver_script.exports_sync.trigger_download(download_target, cdn_url, aes_key, native_target_path, file_type)
        except Exception:
            self.receive_ctx.reset_download_requested(cdn_url)
            return ""

        try:
            numeric_result = int(str(result).strip())
        except Exception:
            numeric_result = None

        if result in (None, False, 0, "0") or (numeric_result is not None and numeric_result <= 0):
            self.receive_ctx.reset_download_requested(cdn_url)
            return ""

        return native_target_path

    def get_messages(self, timeout_seconds: float = 0.0, drain_all: bool = False) -> dict:
        self.ensure_receiver_alive()
        messages = []

        if drain_all:
            while True:
                try:
                    messages.append(self.enrich_media_message(self.receive_ctx.incoming_messages.get_nowait()))
                except queue.Empty:
                    break

        if timeout_seconds > 0:
            deadline = time.time() + timeout_seconds
            while True:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                try:
                    messages.append(self.enrich_media_message(self.receive_ctx.incoming_messages.get(timeout=remaining)))
                except queue.Empty:
                    break

            if not messages:
                return {"status": "empty", "messages": []}
            return {"status": "ok", "messages": messages}

        if messages:
            return {"status": "ok", "messages": messages}

        try:
            message = self.enrich_media_message(self.receive_ctx.incoming_messages.get_nowait())
        except queue.Empty:
            return {"status": "empty", "message": None}

        return {"status": "ok", "message": message}


class WeChatHandler(BaseHTTPRequestHandler):
    runtime = None

    def do_GET(self) -> None:
        if self.path != "/status":
            self.write_json(404, {"status": "error", "error": "not found"})
            return
        try:
            self.write_json(200, self.runtime.status())
        except Exception as exc:
            self.write_json(500, {"status": "error", "error": str(exc)})

    def do_POST(self) -> None:
        if self.path == "/shutdown":
            if self.client_address[0] not in ("127.0.0.1", "::1", "localhost"):
                self.write_json(403, {"status": "error", "error": "forbidden"})
                return
            self.write_json(200, {"status": "ok", "message": "daemon stopping"})
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return

        if self.path not in ("/send", "/get"):
            self.write_json(404, {"status": "error", "error": "not found"})
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(content_length)
        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except json.JSONDecodeError:
            self.write_json(400, {"status": "error", "error": "invalid json"})
            return

        if self.path == "/send":
            target = payload.get("to", "")
            message = payload.get("message", "")
            at_user = payload.get("at_user", "")
            if not target or not message:
                self.write_json(400, {"status": "error", "error": "缺少 to 或 message"})
                return

            try:
                result = self.runtime.send_text(target, message, at_user)
                self.write_json(200, result)
            except TimeoutError as exc:
                self.write_json(504, {"status": "error", "error": str(exc)})
            except Exception as exc:
                self.write_json(500, {"status": "error", "error": str(exc)})
            return

        try:
            timeout_seconds = float(payload.get("timeout", 0))
        except (TypeError, ValueError):
            self.write_json(400, {"status": "error", "error": "invalid timeout"})
            return
        drain_all = bool(payload.get("all", False))

        try:
            result = self.runtime.get_messages(timeout_seconds=timeout_seconds, drain_all=drain_all)
            self.write_json(200, result)
        except Exception as exc:
            self.write_json(500, {"status": "error", "error": str(exc)})

    def log_message(self, format, *args) -> None:
        return

    def write_json(self, status_code: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run_daemon(args) -> int:
    script_path = pathlib.Path(args.script).expanduser().resolve()
    if not script_path.exists():
        raise SystemExit(f"找不到脚本: {script_path}")
    receiver_script_path = pathlib.Path(args.receiver_script).expanduser().resolve()
    if not receiver_script_path.exists():
        raise SystemExit(f"找不到接收脚本: {receiver_script_path}")

    host, port = parse_host_port(args.listen)
    try:
        server = ThreadingHTTPServer((host, port), WeChatHandler)
    except OSError as exc:
        raise SystemExit(f"daemon 启动失败: {exc}") from exc

    runtime = None
    start_error = None
    try:
        for attempt in range(3):
            runtime = WeChatRuntime(
                gadget_addr=args.gadget_addr,
                script_path=script_path,
                receiver_script_path=receiver_script_path,
                verbose=args.verbose,
                send_timeout=args.send_timeout,
            )
            try:
                runtime.start()
                start_error = None
                break
            except (frida.TransportError, TimeoutError) as exc:
                start_error = exc
                if "timeout" not in str(exc).lower() or attempt == 2:
                    raise
                time.sleep(2.0)
    except Exception:
        server.server_close()
        raise

    if start_error is not None:
        server.server_close()
        raise start_error

    WeChatHandler.runtime = runtime

    print(f"daemon 已启动: http://{args.listen}")
    print("请先在微信里手动发送一条普通文本消息，用于捕获模板。")
    print("模板就绪后，可重复执行: ./wechat send \"这是消息\" -to \"truemang\"")
    print("接收消息通过独立 receiver.js 挂载，可执行: ./wechat get")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("收到退出信号，正在关闭 daemon")
    finally:
        server.server_close()
        if not runtime.close():
            print("Frida 清理超时，强制退出 daemon")
            sys.stdout.flush()
            sys.stderr.flush()
            os._exit(0)
    return 0


def run_send(args) -> int:
    response = post_json(
        args.daemon_addr,
        "/send",
        {
            "to": args.to,
            "message": args.message,
            "at_user": "",
            "client_timeout": args.send_timeout + 5,
        },
    )
    print(json.dumps(response, ensure_ascii=False))
    return 0


def run_get(args) -> int:
    if args.timeout <= 0:
        response = post_json(
            args.daemon_addr,
            "/get",
            {
                "timeout": 0,
                "all": args.all,
                "client_timeout": MEDIA_RESOLVE_TIMEOUT_SECONDS + 5,
            },
        )
        if response.get("status") == "ok":
            messages = response.get("messages")
            if messages is None:
                single = response.get("message")
                messages = [] if single is None else [single]
            for message in messages:
                formatted = format_incoming_message(message)
                if args.as_json:
                    print(json.dumps(formatted, ensure_ascii=False), flush=True)
                else:
                    print(render_incoming_message_text(formatted), flush=True)
        else:
            if args.as_json:
                print(json.dumps(response, ensure_ascii=False))
            else:
                print("- status: empty")
        return 0

    deadline = time.time() + args.timeout
    poll_interval = min(1.0, args.timeout)
    printed = 0

    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            break

        wait_timeout = min(poll_interval, remaining)
        response = post_json(
            args.daemon_addr,
            "/get",
            {
                "timeout": wait_timeout,
                "all": True,
                "client_timeout": wait_timeout + MEDIA_RESOLVE_TIMEOUT_SECONDS + 5,
            },
        )

        if response.get("status") != "ok":
            continue

        messages = response.get("messages")
        if messages is None:
            single = response.get("message")
            messages = [] if single is None else [single]

        for message in messages:
            formatted = format_incoming_message(message)
            if args.as_json:
                print(json.dumps(formatted, ensure_ascii=False), flush=True)
            else:
                print(render_incoming_message_text(formatted), flush=True)
                print("", flush=True)
            printed += 1

    if printed == 0:
        if args.as_json:
            print(json.dumps({"status": "empty", "messages": []}, ensure_ascii=False))
        else:
            print("- status: empty")
    return 0


def run_status(args) -> int:
    response = get_json(args.daemon_addr, "/status")
    print(json.dumps(response, ensure_ascii=False))
    return 0


def run_daemon_stop(args) -> int:
    response = post_json(
        args.daemon_addr,
        "/shutdown",
        {
            "client_timeout": 5,
        },
    )
    print(json.dumps(response, ensure_ascii=False))
    return 0


def add_common_send_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("message", help="要发送的消息内容")
    parser.add_argument("-to", "--to", dest="to", required=True, help="接收人，例如 truemang")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="wechat", description="WeChat Frida CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    daemon_parser = subparsers.add_parser("start", help="启动常驻发送 daemon")
    daemon_parser.add_argument(
        "--listen",
        default=DEFAULT_DAEMON_ADDR,
        help=f"daemon 监听地址，默认 {DEFAULT_DAEMON_ADDR}",
    )
    daemon_parser.add_argument(
        "--gadget-addr",
        default="127.0.0.1:27042",
        help="Frida Gadget 地址，默认 127.0.0.1:27042",
    )
    daemon_parser.add_argument(
        "--script",
        default=str(DEFAULT_SCRIPT_PATH),
        help=f"Frida 脚本路径，默认 {DEFAULT_SCRIPT_PATH}",
    )
    daemon_parser.add_argument(
        "--receiver-script",
        default=str(DEFAULT_RECEIVER_SCRIPT_PATH),
        help=f"接收脚本路径，默认 {DEFAULT_RECEIVER_SCRIPT_PATH}",
    )
    daemon_parser.add_argument(
        "--send-timeout",
        type=float,
        default=20,
        help="每次发送等待 finish 的超时时间，单位秒，默认 20",
    )
    daemon_parser.add_argument("-v", "--verbose", action="store_true", help="输出 JS 日志")
    daemon_parser.set_defaults(func=run_daemon)

    send_parser = subparsers.add_parser("send", help="通过本地 daemon 发送文本消息")
    add_common_send_arguments(send_parser)
    send_parser.add_argument(
        "--daemon-addr",
        default=DEFAULT_DAEMON_ADDR,
        help=f"本地 daemon 地址，默认 {DEFAULT_DAEMON_ADDR}",
    )
    send_parser.add_argument(
        "--send-timeout",
        type=float,
        default=20,
        help="客户端等待 daemon 返回的超时时间，单位秒，默认 20",
    )
    send_parser.set_defaults(func=run_send)

    get_parser = subparsers.add_parser("get", help="从本地 daemon 读取接收消息")
    get_parser.add_argument(
        "--daemon-addr",
        default=DEFAULT_DAEMON_ADDR,
        help=f"本地 daemon 地址，默认 {DEFAULT_DAEMON_ADDR}",
    )
    get_parser.add_argument(
        "--timeout",
        type=float,
        default=0,
        help="持续接收消息的秒数，超时后统一返回，默认 0 表示立即返回",
    )
    get_parser.add_argument(
        "--all",
        action="store_true",
        help="开始等待前先把当前队列里的历史消息一并取出",
    )
    get_parser.add_argument(
        "-json",
        "--json",
        dest="as_json",
        action="store_true",
        help="按 JSON 格式输出消息",
    )
    get_parser.set_defaults(func=run_get)

    status_parser = subparsers.add_parser("status", help="查看 daemon 状态")
    status_parser.add_argument(
        "--daemon-addr",
        default=DEFAULT_DAEMON_ADDR,
        help=f"本地 daemon 地址，默认 {DEFAULT_DAEMON_ADDR}",
    )
    status_parser.set_defaults(func=run_status)

    daemon_stop_parser = subparsers.add_parser("stop", help="停止本地 daemon")
    daemon_stop_parser.add_argument(
        "--daemon-addr",
        default=DEFAULT_DAEMON_ADDR,
        help=f"本地 daemon 地址，默认 {DEFAULT_DAEMON_ADDR}",
    )
    daemon_stop_parser.set_defaults(func=run_daemon_stop)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
