package main

import (
	"encoding/json"
	"fmt"
	"log"
)

func Download(rawMsg []byte) error {
	downloadReq := new(DownloadRequest)
	err := json.Unmarshal(rawMsg, downloadReq)
	if err != nil {
		log.Printf("JSON解析失败: %v\n", err)
		return err
	}
	
	fmt.Printf("下载文件: %s, %d, %s\n", downloadReq.FileID, len(downloadReq.Media), downloadReq.CDNURL[:10])
	if downloadReqInter, ok := userID2FileMsgMap.Load(downloadReq.CDNURL); ok {
		downloadReq = downloadReqInter.(*DownloadRequest)
		downloadReq.Media = append(downloadReq.Media, downloadReq.Media...)
	} else {
		userID2FileMsgMap.Store(downloadReq.CDNURL, downloadReq)
	}
	
	return nil
}
