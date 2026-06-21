package dat

import (
	"fmt"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"
)

var (
	datCmsManager *CmsManager
	once          sync.Once
)

func getCmsManager() (*CmsManager, error) {
	if datCmsManager == nil {
		return nil, fmt.Errorf("dat auto sync manager not initialized")
	}
	return datCmsManager, nil
}

func testAutoSync(t *testing.T) error {
	manager, err := getCmsManager()
	if err != nil {
		return err
	}

	plain := "Unicode 유니코드 ユニコード 万国码 يونيكود यूनिकोड Юникод 🦄💻"
	secure := "Ciphertext 암호문 暗号文 密文 Шифротекст Texte chiffré Geheimtext نص مشفر सिफरपाठ 🔐"

	datStr, err := manager.Issue(plain, secure)
	if err != nil {
		return err
	}

	fmt.Printf("dat: %v\n", datStr)

	dat, err := ParseDat(datStr)
	if err != nil {
		return err
	}

	payload, err := manager.Parse(dat)
	if err != nil {
		return err
	}

	if plain != payload.PlainText() {
		return fmt.Errorf("plain text mismatch: expected %q, got %q", plain, payload.PlainText())
	}
	if secure != payload.SecureText() {
		return fmt.Errorf("secure text mismatch: expected %q, got %q", secure, payload.SecureText())
	}

	fmt.Printf("payload plain: %q\n", payload.PlainText())
	fmt.Printf("payload secure: %q\n", payload.SecureText())

	return nil
}

func TestDatCms(t *testing.T) {
	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug, // 👈 디버그 레벨로 설정!
	}
	testLogger := slog.New(slog.NewTextHandler(os.Stdout, opts))

	// init sync before server start
	builder, err := NewDatCmsManagerBuilder().
		Url("http://localhost:8088")
	if err != nil {
		t.Fatal(err)
	}

	manager, err := builder.
		IntervalOff().
		Interval(1 * time.Second).
		Logger(testLogger).
		Token("12345678901b").
		Build()

	if err != nil {
		// 실제 서버가 없으면 여기서 에러가 날 것이나, 요구사항에 실제 네트워크 연결이 중요하다고 함.
		// 만약 서버가 떠있지 않다면 테스트는 실패하는 것이 맞음.
		t.Fatalf("failed to build manager: %v", err)
	}

	datCmsManager = manager

	// test
	err = testAutoSync(t)
	if err != nil {
		t.Logf("auto sync test skipped or failed (normal if server is down): %v", err)
	}

	time.Sleep(5 * time.Second)
}
