package beat

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/libbeat/logp"
)

type Config struct {
	RequestURL      string
	BearerToken     string
	RefreshTokenURL string
	ClientID        string
	ClientSecret    string
	ExpiresIn       int
	LogStashURL     string
}

func LoadConfig() (*Config, error) {
	config := &Config{
		ClientID:        "PAR_testapiprojetetudiant_b469c4477085d6dc448db5b821c0ef0c0ae1d7c89fadff5a75bcfd585bc8c0d0",
		ClientSecret:    "77ff641b78c0ddb3150606b48cf706cb564565dc8c43aa16ea594df58454dcac",
		RequestURL:      "https://api.pole-emploi.io/partenaire/offresdemploi/v2/offres/search?range=0-10",
		RefreshTokenURL: "https://entreprise.pole-emploi.fr/connexion/oauth2/access_token?realm=/partenaire",
		LogStashURL:     "http://logstash:5044",
	}
	return config, nil
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Scope        string `json:"scope"`
}

type CustomBeat struct {
	done   chan struct{}
	config Config
	client beat.Client
}

func New(b *beat.Beat, cfg *common.Config) (beat.Beater, error) {
	config, err := LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("Error loading config: %v", err)
	}

	bt := &CustomBeat{
		done:   make(chan struct{}),
		config: *config,
	}
	return bt, nil
}

func (beat *CustomBeat) Run(b *beat.Beat) error {
	logp.Info("mycustombeat is running! Hit CTRL-C to stop it.")
	var err error
	beat.client, err = b.Publisher.Connect()
	if err != nil {
		return err
	}
	for {
		select {
		case <-beat.done:
			return nil
		default:
			if err := beat.refreshToken(&beat.config); err != nil {
				logp.Err("Error refreshing token: %v", err)
				continue
			}
			if err := beat.fetch(); err != nil {
				logp.Err("Error fetching data: %v", err)
				continue
			}
			// You can also create and publish an event here based on the fetched data
			time.Sleep(10 * time.Second) // Adjust the frequency as needed
		}
	}
}

func (beat *CustomBeat) Stop() {
	beat.client.Close()
	close(beat.done)
}

func (beat *CustomBeat) refreshToken(config *Config) error {
	client := &http.Client{}
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", config.ClientID)
	data.Set("client_secret", config.ClientSecret)
	data.Set("scope", "api_offresdemploiv2 o2dsoffre")
	req, err := http.NewRequest("POST", config.RefreshTokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return err
	}
	accessToken, ok := response["access_token"].(string)
	if !ok {
		return fmt.Errorf("access token not found in response")
	}
	config.BearerToken = "Bearer " + accessToken
	fmt.Println("New token:", config.BearerToken)
	return nil
}

func (beat *CustomBeat) fetch() error {
	client := &http.Client{}
	req, err := http.NewRequest("GET", beat.config.RequestURL, nil)
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", beat.config.BearerToken)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode == 401 {
		return fmt.Errorf("unauthorized")
	}
	defer resp.Body.Close()
	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return err
	}
	fmt.Println("got new response at time:", time.Now().Format(time.RFC3339Nano))
	return nil
}

func main() {
	err := beat.Run("beatmybeat", "1.0.0", New) // Corrected here
	if err != nil {
		logp.Err("Error running beatmybeat: %v", err)
		os.Exit(1)
	}
}
