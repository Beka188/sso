package storage

import "errors"

var ErrUserNotFound = errors.New("user not found")
var ErrAlreadyExists = errors.New("user already exists")
var ErrAppNotFound = errors.New("app not found")
