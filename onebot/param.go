package main

import (
	"encoding/xml"
	"sync"
	
	"github.com/frida/frida-go/frida"
)

// 全局变量，保持 Frida 脚本对象
var (
	fridaScript *frida.Script
	session     *frida.Session
	taskId      = int64(0x20000000)
	myWechatId  = ""
	
	msgChan    = make(chan *SendMsg, 10)
	finishChan = make(chan struct{})
	
	config = &Config{}
	
	userID2NicknameMap sync.Map
	userID2FileMsgMap  sync.Map
)

type WechatMessage struct {
	GroupId     string     `json:"group_id"`
	SelfID      string     `json:"self_id"`
	UserID      string     `json:"user_id"`
	Sender      *Sender    `json:"sender"`
	Time        int64      `json:"time"`
	PostType    string     `json:"post_type"`
	MessageId   string     `json:"message_id"`
	Message     []*Message `json:"message"`
	MsgResource string     `json:"msgsource"`
	RawMessage  string     `json:"raw_message"`
	ShowContent string     `json:"show_content"`
}

type Sender struct {
	UserID   string `json:"user_id"`
	Nickname string `json:"nickname"`
}

type SendMsg struct {
	UserId  string
	GroupID string
	Content string
	Type    string
	AtUser  string
}

// SendRequest 请求结构体
type SendRequest struct {
	Message []*Message `json:"message"`
	UserID  string     `json:"user_id"`
	GroupID string     `json:"group_id"`
}

type Message struct {
	Type string           `json:"type"`
	Data *SendRequestData `json:"data"`
}

type SendRequestData struct {
	Id    string `json:"id,omitempty"`
	Text  string `json:"text,omitempty"`
	File  string `json:"file,omitempty"`
	URL   string `json:"url,omitempty"`
	QQ    string `json:"qq,omitempty"`
	Media []byte `json:"media,omitempty"`
}

type Config struct {
	FridaType       string `json:"frida_type"`
	SendURL         string `json:"send_url"`
	ReceiveHost     string `json:"receive_host"`
	FridaGadgetAddr string `json:"frida_gadget_addr"`
	WechatPid       int    `json:"wechat_pid"`
	OnebotToken     string `json:"onebot_token"`
	ImagePath       string `json:"image_path"`
	ConnType        string `json:"conn_type"`
	SendInterval    int    `json:"send_interval"`
	
	WechatConf string `json:"wechat_conf"`
}

// VoiceMsg 对应外层的 <msg> 标签
type VoiceMsg struct {
	XMLName  xml.Name      `xml:"msg"`
	VoiceMsg *VoiceMsgInfo `xml:"voicemsg"`
}

// VoiceMsgInfo 对应内部的 <voicemsg> 标签及其属性
type VoiceMsgInfo struct {
	EndFlag      int    `xml:"endflag,attr"`
	CancelFlag   int    `xml:"cancelflag,attr"`
	ForwardFlag  int    `xml:"forwardflag,attr"`
	VoiceFormat  int    `xml:"voiceformat,attr"`
	VoiceLength  int    `xml:"voicelength,attr"`
	Length       int    `xml:"length,attr"`
	BufID        int    `xml:"bufid,attr"`
	AESKey       string `xml:"aeskey,attr"`
	VoiceURL     string `xml:"voiceurl,attr"`
	VoiceMD5     string `xml:"voicemd5,attr"`
	ClientMsgID  string `xml:"clientmsgid,attr"`
	FromUserName string `xml:"fromusername,attr"`
}

// FileMsg 对应 <msg> 标签
type FileMsg struct {
	XMLName xml.Name `xml:"msg"`
	Image   Image    `xml:"img"`
}

// Image 对应 <img> 标签及其属性和子节点
type Image struct {
	// 属性（Attributes）
	AesKey      string `xml:"aeskey,attr"`
	EncryVer    int    `xml:"encryver,attr"`
	ThumbAesKey string `xml:"cdnthumbaeskey,attr"`
	ThumbURL    string `xml:"cdnthumburl,attr"`
	Length      int    `xml:"length,attr"`
	Md5         string `xml:"md5,attr"`
	HDHeight    int    `xml:"cdnhdheight,attr"`
	HDWidth     int    `xml:"cdnhdwidth,attr"`
	MidImgURL   string `xml:"cdnmidimgurl,attr"`
	
	// 子节点
	SecHashInfo string `xml:"secHashInfoBase64"`
	Live        Live   `xml:"live"`
}

// Live 对应 <live> 标签
type Live struct {
	Duration int    `xml:"duration"`
	Size     int    `xml:"size"`
	FileID   string `xml:"fileid"`
}

type DownloadRequest struct {
	FileID string `json:"file_id"`
	Media  []byte `json:"media"`
	CDNURL string `json:"cdn_url"`
}

type ScriptMessage struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}
