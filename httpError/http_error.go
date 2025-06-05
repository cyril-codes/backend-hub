package httperror

import (
	"net/http"
)

type HttpError struct {
	error
	Code int
}

func New(code int, err error) *HttpError {
	return &HttpError{
		error: err,
		Code:  code,
	}
}

func BadRequest(err error) *HttpError {
	return New(http.StatusBadRequest, err)
}

func Conflict(err error) *HttpError {
	return New(http.StatusConflict, err)
}

func InternalError(err error) *HttpError {
	return New(http.StatusInternalServerError, err)
}

func Unauthorized(err error) *HttpError {
	return New(http.StatusUnauthorized, err)
}
