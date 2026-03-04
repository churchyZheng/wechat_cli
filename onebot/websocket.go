package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"runtime/debug"
	"strings"
	"time"
	
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{}
var conn *websocket.Conn

type OneBotWSMsg struct {
	Action string    `json:"action"`
	Echo   string    `json:"echo"`
	Params *WSParams `json:"params"`
}

type WSParams struct {
	Message interface{} `json:"message"`
	UserID  string      `json:"user_id"`
	GroupID string      `json:"group_id"`
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	var err error
	conn, err = upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("升级失败:", err)
		return
	}
	defer conn.Close()
	
	fmt.Println("机器人已连接！")
	
	for {
		m := new(OneBotWSMsg)
		_, msgByte, err := conn.ReadMessage()
		if err != nil {
			log.Println("读取失败:", err)
			break
		}
		
		fmt.Println("收到消息: " + string(msgByte))
		err = json.Unmarshal(msgByte, m)
		if err != nil {
			log.Println("解析失败:", err)
			continue
		}
		
		switch m.Action {
		case "get_login_info":
			err = conn.WriteJSON(map[string]any{
				"echo":   m.Echo,
				"status": "ok",
				"data": map[string]any{
					"user_id":  myWechatId,
					"nickname": myWechatId,
				},
			})
			if err != nil {
				log.Println("写入失败:", err)
				break
			}
		case "send_private_msg", "send_group_msg":
			err = SendWS(m.Params)
			if err != nil {
				log.Println("发送失败:", err)
				break
			}
			
		}
		
	}
	
}

func SendWebSocketMsg(jsonData []byte) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("panic: %v, %v\n", r, string(debug.Stack()))
		}
	}()
	
	time.Sleep(time.Duration(config.SendInterval) * time.Millisecond)
	
	jsonReq, err := HandleMsg(jsonData)
	if err != nil {
		log.Printf("JSON 序列化失败: %v\n", err)
		return
	}
	if jsonReq == nil {
		return
	}
	
	fmt.Printf("发送数据: %s\n", string(jsonReq))
	err = conn.WriteMessage(websocket.TextMessage, jsonReq)
	if err != nil {
		log.Printf("发送消息失败: %v\n", err)
		return
	}
}

func SendWS(req *WSParams) error {
	sendContent := ""
	atUserID := ""
	if msg, ok := req.Message.(string); ok {
		sendContent = msg
	} else {
		bytes, err := json.Marshal(req.Message)
		if err != nil {
			log.Printf("JSON 序列化失败: %v\n", err)
			return err
		}
		msgs := make([]*Message, 0)
		err = json.Unmarshal(bytes, &msgs)
		if err != nil {
			log.Printf("JSON 反序列化失败: %v\n", err)
			return err
		}
		
		for _, v := range msgs {
			if v.Type == "text" {
				sendContent += v.Data.Text
			} else if v.Type == "at" {
				if req.GroupID != "" {
					if nicknameInter, ok := userID2NicknameMap.Load(req.GroupID + "_" + v.Data.QQ); ok {
						sendContent += fmt.Sprintf("@%s\u2005", nicknameInter.(string))
						atUserID += v.Data.QQ + ","
					}
				}
				
			} else if v.Type == "image" {
				msgChan <- &SendMsg{
					UserId:  req.UserID,
					GroupID: req.GroupID,
					Content: v.Data.File,
					Type:    v.Type,
				}
			}
		}
		
	}
	
	if sendContent != "" {
		msgChan <- &SendMsg{
			UserId:  req.UserID,
			GroupID: req.GroupID,
			Content: sendContent,
			Type:    "text",
			AtUser:  strings.TrimRight(atUserID, ","),
		}
	}
	
	return nil
}

func testWebSocket(w http.ResponseWriter, r *http.Request) {
	jsonData, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("读取消息失败: %v\n", err)
		return
	}
	
	err = conn.WriteMessage(websocket.TextMessage, jsonData)
	if err != nil {
		log.Printf("发送消息失败: %v\n", err)
		return
	}
}
