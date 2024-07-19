package auth

import (
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/context"
	"log/slog"
	"sso/internal/domain/models"
	"sso/internal/lib/jwt"
	"sso/internal/lib/logger/sl"
	"sso/internal/storage"
	"time"
)

type Auth struct {
	log          *slog.Logger
	UserSaver    UserSaver
	UserProvider UserProvider
	AppProvider  AppProvider
	TokenTTL     time.Duration
}

type UserSaver interface {
	SaveUser(ctx context.Context, email string, passHash []byte) (uid int64, err error)
}

type UserProvider interface {
	ProvideUser(ctx context.Context, email string) (user models.User, err error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
}

type AppProvider interface {
	ProvideApp(ctx context.Context, appID int32) (app models.App, err error)
}

func New(log *slog.Logger, userSaver UserSaver, userProvider UserProvider, appProvider AppProvider, tokenTTL time.Duration) *Auth {
	return &Auth{
		log:          log,
		UserSaver:    userSaver,
		UserProvider: userProvider,
		AppProvider:  appProvider,
		TokenTTL:     tokenTTL,
	}
}

func (a *Auth) RegisterNewUser(ctx context.Context, email, password string) (int64, error) {
	const op = "auth.RegisterNewUser"
	log := a.log.With(
		slog.String("op", op),
		slog.String("email", email),
	)
	log.Info("registering new user")

	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("Failed to generate password hash", sl.Err(err))
		return 0, fmt.Errorf("%w: %s", err, op)
	}

	id, err := a.UserSaver.SaveUser(ctx, email, passHash)
	if err != nil {
		if errors.Is(err, storage.ErrAlreadyExists) {
			a.log.Error("User already exists", sl.Err(err))
		}
		a.log.Error("Failed to save user", sl.Err(err))
		return 0, fmt.Errorf("%w: %s", err, op)
	}

	log.Info("new user registered")

	return id, nil
}

var ErrInvalidCredentials = errors.New("invalid credentials")

func (a *Auth) Login(ctx context.Context, email, password string, appID int32) (string, error) {
	const op = "auth.Login"
	log := a.log.With(
		slog.String("op", op),
		slog.String("email", email),
	)
	log.Info("looking up user")

	user, err := a.UserProvider.ProvideUser(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			a.log.Warn("invalid credentials", sl.Err(err))
			return "", fmt.Errorf("%s %w", op, ErrInvalidCredentials)
		}

		a.log.Error("Failed to get user", sl.Err(err))
		return "", fmt.Errorf("%w: %s", err, op)
	}

	if err = bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		a.log.Warn("Invalid credentials", sl.Err(err))
		return "", fmt.Errorf("%s %w", op, ErrInvalidCredentials)
	}

	app, err := a.AppProvider.ProvideApp(ctx, appID)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			a.log.Warn("invalid credentials", sl.Err(err))
			return "", fmt.Errorf("%s %w", op, ErrInvalidCredentials)
		}
		a.log.Error("Failed to find app", sl.Err(err))
		return "", fmt.Errorf("%s %w", op, err)
	}
	log.Info("user login successfully")

	jwtToken, err := jwt.NewToken(user, app, time.Duration(100))
	if err != nil {
		log.Error("Failed to create token", sl.Err(err))
	}

	return jwtToken, nil
}

func (a *Auth) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	const op = "auth.IsAdmin"
	log := a.log.With(
		slog.String("op", op),
		slog.Int64("user_id", userID),
	)
	log.Info("checking if user is admin")

	isAdmin, err := a.UserProvider.IsAdmin(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			a.log.Warn("user not found")
			return false, fmt.Errorf("%s %w", op, ErrInvalidCredentials)
		}
		return false, fmt.Errorf("%s %w", op, err)
	}
	log.Info("checked. The user is with id", slog.Bool("is_admin", isAdmin))

	return isAdmin, nil
}
