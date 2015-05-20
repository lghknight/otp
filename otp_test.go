package otp

import (
	"path/filepath"
	"runtime"
	"testing"
)

func assert(t *testing.T, condition bool, msg string, v ...interface{}) {
	if !condition {
		_, file, line, _ := runtime.Caller(1)
		t.Logf("\033[31m%s:%d: "+msg+"\033[39m\n\n",
			append([]interface{}{filepath.Base(file), line}, v...)...)
		t.FailNow()
	}
}

func TestOTPAuth(t *testing.T) {
	Init("../data")
	op := new(OTPzc)
	var code string = ""
	c, _ := op.OTPAuth("yang", "sss", code, C200)
	if c != OTP_SUCCESS {
		t.FailNow()
	}
	c, _ = op.OTPAuth("yang", "sss", code, C200)
	if c != OTP_ERR_REPLAY {
		t.FailNow()
	}
	code = ""
	c, _ = op.OTPAuth("yang", "sss", code, C200)
	if c != OTP_ERR_CHECK_PWD {
		t.FailNow()
	}
	code = ""
	c, _ = op.OTPAuth("yang", "sss", code, C200)
	if c != OTP_ERR_SYN_PWD {
		t.FailNow()
	}
}

func BenchmarkOTPAuth(b *testing.B) {
	b.StopTimer()
	Init("../data")
	op := new(OTPzc)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		op.OTPAuth("yang", "sss", "392091", C200)
	}
	b.StopTimer()
}
