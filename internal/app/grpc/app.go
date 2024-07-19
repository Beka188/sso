package grpcapp

import (
	"fmt"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"log/slog"
	"net"
	"sso/internal/domain/models"
	authgrpc "sso/internal/grpc/auth"
	"sso/internal/lib/jwt"
	"time"
)

type AuthImpl struct {
}

func (a AuthImpl) Login(ctx context.Context, email string, password string, appId int32) (string, error) {
	//TODO ...
	// Implement the logic here
	token, err := jwt.NewToken(models.User{Email: email, PassHash: []byte(password)}, models.App{ID: 1, Name: "f"}, time.Duration(100))
	if err != nil {
		return "", err
	}
	return token, nil
}

func (a AuthImpl) RegisterNewUser(ctx context.Context, email string, password string) (int64, error) {
	// TODO ...
	return -1, nil
}

func (a AuthImpl) IsAdmin(ctx context.Context, userId int64) (bool, error) {
	// TODO ...
	return false, nil
}

type App struct {
	log        *slog.Logger
	gRPCServer *grpc.Server
	port       int
}

func New(log *slog.Logger, port int) *App {
	gRPCServer := grpc.NewServer()
	authgrpc.Register(gRPCServer, AuthImpl{})
	return &App{log, gRPCServer, port}
}

func (a *App) Run() error {
	const op = "grpcapp.Run"
	log := a.log.With(
		slog.String("op", op),
		slog.Int("port", a.port),
	)
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", a.port))
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("grpc server is running", slog.String("addr", l.Addr().String()))

	if err := a.gRPCServer.Serve(l); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

func (a *App) Stop() {
	const op = "grpcapp.Stop"

	a.log.With(slog.String("op", op)).Info("grpc server is stopping", slog.Int("port", a.port))

	a.gRPCServer.GracefulStop()

}
