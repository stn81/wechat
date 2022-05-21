package wxweb

import "fmt"

type BizError struct {
	error
}

func NewBizError(format string, args ...interface{}) *BizError {
	return &BizError{
		error: fmt.Errorf(format, args...),
	}
}

func IsBizError(err error) bool {
	_, ok := err.(*BizError)
	return ok
}
