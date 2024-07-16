package services

import (
	"context"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"sso/internal/domain/models"
	"sso/internal/lib/logger/sl"
	"time"
)

//type UserStorage interface {
//	SaveUser(ctx context.Context,
//		user *models.User,
//	) (uid int64, err error)
//	User(ctx context.Context,
//		email string,
//	) (models.User, error)
//}

type UserSaver interface {
	SaveUser(ctx context.Context,
		email string,
		password []byte,
	) (uid int64, err error)
}

type UserProvider interface {
	User(ctx context.Context,
		email string) (models.User, error)
}

type AppProvider interface {
	App(ctx context.Context,
		appID int) (models.App, error)
}

type Auth struct {
	log          *slog.Logger
	userSaver    UserSaver
	userProvider UserProvider
	appProvider  AppProvider
	TokenTTL     time.Duration
}

func New(
	log *slog.Logger,
	userSaver UserSaver,
	userProvider UserProvider,
	appProvider AppProvider,
	tokenTTL time.Duration) *Auth {
	return &Auth{log, userSaver, userProvider, appProvider, tokenTTL}
}

func (a *Auth) RegisterNewUser(ctx context.Context, email string, password string) (int64, error) {
	const op = "Auth.RegisterNewUser"
	log := a.log.With(
		slog.String("op", op),
		slog.String("email", email),
	)

	log.Info("RegisterNewUser")

	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to hash password", sl.Err(err))
		return 0, fmt.Errorf("%s %w", op, err)
	}

	id, err := a.userSaver.SaveUser(ctx, email, passHash)
	if err != nil {
		log.Error("failed to save user", sl.Err(err))

		return 0, fmt.Errorf("%s %w", op, err)
	}
	return id, nil
}
