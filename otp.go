package otp

/*
CGO docs
http://stackoverflow.com/questions/28037827/how-to-use-a-relative-path-for-ldflags-in-golang
using libetotpverify.a
*/

/*
#cgo CFLAGS: -I${SRCDIR}/
#cgo LDFLAGS: -Wl,-Bstatic -L${SRCDIR}/ -letotpverify -Wl,-Bdynamic -ldl -lstdc++
#include "libetotpverify.h"
#include <stdlib.h>
*/
import "C"

import (
	"bufio"
	"errors"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"
)

const (
	OTP_SUCCESS               = 0x00000000 //操作成功
	OTP_ERR_INVALID_PARAMETER = 0x00000001 //参数无效
	OTP_ERR_CHECK_PWD         = 0x00000002 //认证失败
	OTP_ERR_SYN_PWD           = 0x00000003 //同步失败
	OTP_ERR_REPLAY            = 0x00000004 //动态口令被重放

	C200 int = 0
	Z01  int = 1
)

/*
type OTPMap struct {
	lock	*sync.RWMutex
	otm		map[interface {}]interface {}
}

func newMap() *OTPMap {
	return &OTPMap{
		lock:new(sync.RWMutex),
		otm:make(map[interface {}]interface {}),
	}
}

func (om *OTPMap)get(key interface {}) interface {} {
	om.lock.RLock()
	defer om.lock.RUnlock()

	if v,ok := om.otm[key];ok {
		return v
	}
	return nil
}

func (om *OTPMap)set(key,val interface {}) bool {
	om.lock.Lock()
	defer om.lock.Unlock()
	if v,ok := om.otm[key];!ok {
		om.otm[key] = val
	}else if(v!=val){
		om.otm[key] = val
	}else{
		return false
	}
	return true
}
*/
var gInfo map[string]*Store //暂时使用MAP来做缓存

type Store struct {
	SN         string
	Seed       string
	LastSucc   uint64
	LastDrift  int
	LastFailed string      //最后一次失败的otp
	Locked     int64       //锁定的时间
	Lock       *sync.Mutex //
}

type OTP struct { //调用参数
	key      string
	t        C.uint64_t
	t0       C.uint64_t
	x        C.uint
	drift    C.int
	authwnd  C.int
	lastsucc C.uint64_t
	currsucc C.uint64_t
	currdft  C.int
}

type User struct { //请求的用户数据
	Name    string
	Passwd  string
	OTPCode [2]string
	SN      string
}

type OTPAuther interface {
	OTPAuth() (int64, error)
	OTPSync() (int64, error)
}

type OTPzc struct {
	Param OTP
	User  User
	Type  int
}

func (po *OTPzc) NewOTPzc(usr, passwd, otp, otp1 string, ty int) {
	if _, ok := gInfo[usr]; !ok {
		gInfo[usr] = &Store{
			SN:        "",
			Seed:      "",
			LastSucc:  0,
			LastDrift: 0,
			Lock:      new(sync.Mutex),
		}
	}
	po.User = User{
		Name:    usr,
		Passwd:  passwd,
		OTPCode: [2]string{otp, otp1},
		SN:      gInfo[usr].SN,
	}

	po.Type = ty

	po.Param = OTP{key: gInfo[usr].Seed}
	po.Param.t = C.uint64_t(time.Now().Unix())
	po.Param.t0 = C.uint64_t(0)
	po.Param.x = C.uint(60)
	po.Param.authwnd = C.int(20)
	po.Param.currdft = C.int(0)
	po.Param.currsucc = C.uint64_t(0)
	po.Param.drift = C.int(gInfo[usr].LastDrift)
	po.Param.lastsucc = C.uint64_t(gInfo[usr].LastSucc)
}

func checkLimit(usr string) bool {
	if gInfo[usr].Locked > time.Now().Unix() {
		return false
	}
	return true
}

func (po *OTPzc) OTPAuth(usr, passwd, otp string, ty int) (int64, error) {
	var res int64
	var err error
	//	if !checkLimit(usr){
	//		return 403,errors.New("Auth limited!")
	//	}
	po.NewOTPzc(usr, passwd, otp, "", ty)

	//暂时实现
	gInfo[usr].Lock.Lock()
	defer gInfo[usr].Lock.Unlock()

	//-------------参数转换-----------------
	key := C.CString(po.Param.key)
	defer C.free(unsafe.Pointer(key))
	c_otp := C.CString(po.User.OTPCode[0])
	defer C.free(unsafe.Pointer(c_otp))
	otplen := C.int(len(po.User.OTPCode[0]))

	if po.Type == C200 {
		res = int64(C.ITSecurity_CheckPwdC200(
			key,
			po.Param.t,
			po.Param.t0,
			po.Param.x,
			po.Param.drift,
			po.Param.authwnd,
			po.Param.lastsucc,
			c_otp,
			otplen,
			&po.Param.currsucc,
			&po.Param.currdft))
	} else if po.Type == Z01 {
		res = int64(C.ET_CheckPwdz201(
			key,
			po.Param.t,
			po.Param.t0,
			po.Param.x,
			po.Param.drift,
			po.Param.authwnd,
			po.Param.lastsucc,
			c_otp,
			otplen,
			&po.Param.currsucc,
			&po.Param.currdft))
	}

	switch res {
	case OTP_ERR_CHECK_PWD:
		//认证失败后自动记录otp
		if len(gInfo[po.User.Name].LastFailed) > 5 {
			//已经失败两次，需要去同步
			res, err = po.otpsync(otp)
			if err != nil {
				log.Println("同步失败了", err.Error())
			}
			gInfo[po.User.Name].LastFailed = "" //不管同步结果如何，清空失败otp
		} else {
			//记录失败的otp_code
			gInfo[po.User.Name].LastFailed = po.User.OTPCode[0]
			err = errors.New("Auth Failed")
		}
		gInfo[usr].Locked = time.Now().Add(time.Second * 30).Unix()
		return res, err
	case OTP_ERR_REPLAY:
		//重复认证锁定30秒?
		gInfo[usr].Locked = time.Now().Add(time.Second * 30).Unix()
		return res, errors.New("Code used!")
	case OTP_ERR_INVALID_PARAMETER:
		//参数错误
		gInfo[usr].Locked = time.Now().Add(time.Second * 30).Unix()
		return res, errors.New("Error params!")
	case OTP_SUCCESS:
		//认证成功 将返回值存储到缓存中
		gInfo[po.User.Name].LastSucc = uint64(po.Param.currsucc)
		gInfo[po.User.Name].LastDrift = int(po.Param.currdft)
		gInfo[po.User.Name].LastFailed = ""
		break
	default:
		gInfo[usr].Locked = time.Now().Add(time.Second * 30).Unix()
		break
	}
	return res, nil
}

func (po *OTPzc) otpsync(otp2 string) (int64, error) {
	var res int64
	po.User.OTPCode[0] = gInfo[po.User.Name].LastFailed
	po.User.OTPCode[1] = otp2

	key := C.CString(po.Param.key)
	defer C.free(unsafe.Pointer(key))

	authwind := po.Param.authwnd + 100

	c_otp := C.CString(po.User.OTPCode[0])
	defer C.free(unsafe.Pointer(c_otp))

	otplen := C.int(len(po.User.OTPCode[0]))

	c_otp1 := C.CString(po.User.OTPCode[1])
	defer C.free(unsafe.Pointer(c_otp1))

	otp1len := C.int(len(po.User.OTPCode[1]))

	if po.Type == C200 {
		log.Println("SYNC:", key, po.Param, po.User.OTPCode, authwind)
		res = int64(C.ITSecurity_PSW_SYNC200(
			key,
			po.Param.t,
			po.Param.t0,
			po.Param.x,
			po.Param.drift,
			authwind,
			po.Param.lastsucc,
			c_otp,
			otplen,
			c_otp1,
			otp1len,
			&po.Param.currsucc,
			&po.Param.currdft))
	} else if po.Type == Z01 {
		res = int64(C.ET_Syncz201(
			key,
			po.Param.t,
			po.Param.t0,
			po.Param.x,
			po.Param.drift,
			authwind,
			po.Param.lastsucc,
			c_otp,
			otplen,
			c_otp1,
			otp1len,
			&po.Param.currsucc,
			&po.Param.currdft))
	}
	if res != OTP_SUCCESS {
		return res, errors.New("Sync Failed")
	}
	gInfo[po.User.Name].LastSucc = uint64(po.Param.currsucc)
	gInfo[po.User.Name].LastDrift = int(po.Param.currdft)
	return 0, nil
}

func SeedOpen(fp string) {
	//从文件读取数据，用户名／SN／Seed／最后一次调用信息
	//将数据缓存在MAP中，
	gInfo = make(map[string]*Store)
	f, err := os.OpenFile(fp, os.O_CREATE|os.O_RDWR, os.ModePerm)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	buff := bufio.NewReader(f)
	for {
		line, err := buff.ReadString('\n')
		if err != nil || io.EOF == err {
			break
		}
		var ss []string = strings.Split(line, " ")
		if len(ss) == 5 {
			a, _ := strconv.ParseInt(ss[3], 10, 64)
			b, _ := strconv.ParseInt(ss[4], 10, 64)
			gInfo[ss[0]] = &Store{
				SN:        ss[1],
				Seed:      ss[2],
				LastSucc:  uint64(a),
				LastDrift: int(b),
				Lock:      new(sync.Mutex),
			}
		}
	}
	log.Println(gInfo)
}

func SeedSave(fp string) {
	tmpfile := fp + ".tmp." + strconv.Itoa(os.Getpid())
	f, err := os.OpenFile(tmpfile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, os.ModePerm)
	if err != nil {
		log.Println(err.Error())
		for k, _ := range gInfo {
			log.Println(k, gInfo[k])
		}
		return
	}
	for k, _ := range gInfo {
		log.Println(k, gInfo[k])
		f.WriteString(k + " " + gInfo[k].SN + " " + gInfo[k].Seed + " " + strconv.FormatInt(int64(gInfo[k].LastSucc), 10) + " " + strconv.Itoa(gInfo[k].LastDrift) + "\n")
	}
	f.Close()
	err = os.Rename(tmpfile, fp)
	if err != nil {
		panic(err.Error())
	}
}
