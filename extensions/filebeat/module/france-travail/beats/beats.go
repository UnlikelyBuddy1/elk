package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	RequestURL      string
	RefreshTokenURL string
	ClientID        string
	ClientSecret    string
	LogStashURL     string
}

type RuntimeConfig struct {
	BearerToken string `json:"BearerToken"`
	LastBeat    string `json:"LastBeat"`
	ExpriresIn  int    `json:"ExpriresIn"`
}

func LoadConfig() (*Config, error) {
	err := godotenv.Load("../../../../../.env") // Load .env file
	if err != nil {
		return nil, err
	}
	config := &Config{
		ClientID:        os.Getenv("CLIENT_ID"),
		ClientSecret:    os.Getenv("CLIENT_SECRET"),
		RequestURL:      os.Getenv("BEAT_URL"),
		RefreshTokenURL: os.Getenv("AUTH_URL"),
		LogStashURL:     os.Getenv("LOGSTASH_URL"),
	}
	return config, nil
}
func storeRuntimeConfig(runtimeConfig *RuntimeConfig, runtimePath string) error {
	jsonData, err := json.Marshal(runtimeConfig)
	if err != nil {
		return err
	}
	return os.WriteFile(runtimePath, jsonData, 0600)
}

func retreiveRuntimeConfig(runtimePath string) (*RuntimeConfig, error) {
	data, err := os.ReadFile(runtimePath)
	if err != nil {
		return nil, err
	}
	var runtimeConfig RuntimeConfig
	err = json.Unmarshal(data, &runtimeConfig)
	if err != nil {
		return nil, err
	}
	return &runtimeConfig, nil
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

func refreshToken(config *Config, runtime *RuntimeConfig) error {
	fmt.Println("Refreshing token..")
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
	runtime.BearerToken = "Bearer " + accessToken
	storeRuntimeConfig(runtime, "./runtime.config.json")
	return nil
}

func generateTimeRangeQuery(runtime *RuntimeConfig) (string, error) {
	lastBeatTime, err := time.Parse(time.RFC3339, runtime.LastBeat)
	if err != nil {
		return "", fmt.Errorf("error parsing last beat time: %v", err)
	}
	minCreationDate := lastBeatTime.Format(time.RFC3339)
	maxCreationDate := lastBeatTime.Add(time.Minute).Format(time.RFC3339)
	queryParams := fmt.Sprintf("MINIMUM_CREATION_DATE=%s&MAXIUMUM_CREATION_DATE=%s",
		url.QueryEscape(minCreationDate), url.QueryEscape(maxCreationDate))
	return queryParams, nil
}

func fetch(config *Config, runtime *RuntimeConfig) ([]JobOffer, error) {
	client := &http.Client{}
	timeRange, err := generateTimeRangeQuery(runtime)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("GET", config.RequestURL+"?"+timeRange, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", runtime.BearerToken)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == 401 {
		return nil, fmt.Errorf("unauthorized")
	}
	defer resp.Body.Close()
	var apiResponse APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
		return nil, err
	}
	// Transform each JobOffer
	for i, offer := range apiResponse.Resultats {
		apiResponse.Resultats[i].LieuTravail.Location = Location{
			Lat: offer.LieuTravail.Latitude,
			Lon: offer.LieuTravail.Longitude,
		}
	}
	runtime.LastBeat = time.Now().UTC().Format(time.RFC3339)
	storeRuntimeConfig(runtime, "./runtime.config.json")
	return apiResponse.Resultats, nil
}

func writeToFile(data interface{}, baseDir string) error {
	currentTime := time.Now()
	filename := fmt.Sprintf("log-%s.log", currentTime.Format("2006-01-02"))
	filePath := fmt.Sprintf("%s/%s", baseDir, filename)
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	_, err = file.WriteString(string(jsonData) + "\n")
	return err
}

func isWithinSameMinute(lastBeatTimeStr string) (bool, error) {
	// Parse the last beat time
	lastBeatTime, err := time.Parse(time.RFC3339, lastBeatTimeStr)
	if err != nil {
		return false, fmt.Errorf("error parsing last beat time: %v", err)
	}

	// Get the current time
	currentTime := time.Now().UTC()

	// Check if both times are within the same minute
	return lastBeatTime.Year() == currentTime.Year() &&
		lastBeatTime.Month() == currentTime.Month() &&
		lastBeatTime.Day() == currentTime.Day() &&
		lastBeatTime.Hour() == currentTime.Hour() &&
		lastBeatTime.Minute() == currentTime.Minute(), nil
}

func main() {
	runtimePath := "./runtime.config.json" // Update with actual path
	logBaseDir := "../log/data"            // Directory where log files are store
	config, err := LoadConfig()
	if err != nil {
		fmt.Println("Error loading config:", err)
		os.Exit(1)
	}
	runtime, err := retreiveRuntimeConfig(runtimePath)
	if err != nil {
		fmt.Println("Error retreiving runtime config:", err)
		os.Exit(1)
	}
	if ok, err := isWithinSameMinute(runtime.LastBeat); err != nil {
		fmt.Println("Error parsing last beat time:", err)
		os.Exit(1)
	} else if ok {
		fmt.Println("Skipping fetch as last beat was within the same minute")
		os.Exit(0)
	}
	response, err := fetch(config, runtime)
	if err != nil {
		fmt.Println("Error fetching data:", err)
		if err.Error() == "unauthorized" {
			// Refresh token if unauthorized
			if err := refreshToken(config, runtime); err != nil {
				fmt.Println("Error refreshing token:", err)
				os.Exit(1)
			}
			// Retry fetch
			response, err = fetch(config, runtime)
			if err != nil {
				fmt.Println("Error fetching data after token refresh:", err)
				os.Exit(1)
			}
		} else {
			os.Exit(1)
		}
	}
	// Write fetched data to log file
	if err := writeToFile(response, logBaseDir); err != nil {
		fmt.Println("Error writing to log file:", err)
		os.Exit(1)
	}
}

type JobOffer struct {
	AccessibleTH                bool         `json:"accessibleTH"`
	Agence                      Agence       `json:"agence"`
	Alternance                  bool         `json:"alternance"`
	Appellationlibelle          string       `json:"appellationlibelle"`
	CodeNAF                     string       `json:"codeNAF"`
	Contact                     Contact      `json:"contact"`
	DateActualisation           time.Time    `json:"dateActualisation"`
	DateCreation                time.Time    `json:"dateCreation"`
	Description                 string       `json:"description"`
	DureeTravailLibelle         string       `json:"dureeTravailLibelle"`
	DureeTravailLibelleConverti string       `json:"dureeTravailLibelleConverti"`
	Entreprise                  Entreprise   `json:"entreprise"`
	ExperienceCommentaire       string       `json:"experienceCommentaire"`
	ExperienceExige             string       `json:"experienceExige"`
	ExperienceLibelle           string       `json:"experienceLibelle"`
	ID                          string       `json:"id"`
	Intitule                    string       `json:"intitule"`
	LieuTravail                 LieuTravail  `json:"lieuTravail"`
	NatureContrat               string       `json:"natureContrat"`
	NombrePostes                int          `json:"nombrePostes"`
	OrigineOffre                OrigineOffre `json:"origineOffre"`
	QualificationCode           string       `json:"qualificationCode"`
	QualificationLibelle        string       `json:"qualificationLibelle"`
	RomeCode                    string       `json:"romeCode"`
	RomeLibelle                 string       `json:"romeLibelle"`
	Salaire                     Salaire      `json:"salaire"`
	SecteurActivite             string       `json:"secteurActivite"`
	SecteurActiviteLibelle      string       `json:"secteurActiviteLibelle"`
	TypeContrat                 string       `json:"typeContrat"`
	TypeContratLibelle          string       `json:"typeContratLibelle"`
}
type Agence struct {
	Courriel string `json:"courriel"`
}
type Contact struct {
	Coordonnees1 string `json:"coordonnees1"`
	Coordonnees2 string `json:"coordonnees2"`
	Coordonnees3 string `json:"coordonnees3"`
	Nom          string `json:"nom"`
}
type Entreprise struct {
	EntrepriseAdaptee bool `json:"entrepriseAdaptee"`
}
type LieuTravail struct {
	CodePostal string   `json:"codePostal"`
	Commune    string   `json:"commune"`
	Latitude   float64  `json:"latitude"`
	Libelle    string   `json:"libelle"`
	Longitude  float64  `json:"longitude"`
	Location   Location `json:"location,omitempty"`
}
type Location struct {
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
}
type OrigineOffre struct {
	Origine    string `json:"origine"`
	UrlOrigine string `json:"urlOrigine"`
}
type Salaire struct {
	Complement1 string `json:"complement1"`
	Libelle     string `json:"libelle"`
}
type APIResponse struct {
	Resultats []JobOffer `json:"resultats"`
}
