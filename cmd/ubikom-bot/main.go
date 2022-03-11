package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-message"
	"github.com/emersion/go-message/mail"
	"github.com/ethereum/go-ethereum/ethclient"
	_ "github.com/go-sql-driver/mysql"

	"github.com/regnull/easyecc"
	"github.com/regnull/ubikom-bot/newscache"
	"github.com/regnull/ubikom/bc"
	"github.com/regnull/ubikom/globals"
	"github.com/regnull/ubikom/pb"
	"github.com/regnull/ubikom/protoutil"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	articleTTL       = 24 * time.Hour
	headlinesSubject = "Последние новости о войне"
	header           = `Новости Си-Эн-Эн

Каждая статья имеет номер. Пошлите сообщение с этим номером в теме чтобы получить статью полностью. 

Если вы пользуетесь зашифрованной почтой Ubikom, то ваше взаимодействие с war-info@ubikom.cc не регистрируется и
не отслеживается. Метаинформация о ваших сообщениях всегда зашифрована. Обслуживающие серверы находятся
за пределами РФ. Регестрируйтесь здесь: https://ubikom.cc/ru/index.html.

`
	footer = `
`
)

type arrayFlags []string

func (i *arrayFlags) String() string {
	return "my string representation"
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

type CmdArgs struct {
	DumpServiceURL         string
	LookupServiceURL       string
	DBPassword             string
	BlockchainNodeURL      string
	UseLegacyLookupService bool
	Keys                   arrayFlags
}

type CacheEntry struct {
	Url      string
	Added    time.Time
	Headline string
}

type KeyEntry struct {
	PrivateKey    *easyecc.PrivateKey
	UbikomName    string
	IdentityProof *pb.Signed
}

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "15:04:05", NoColor: true})
	zerolog.SetGlobalLevel(zerolog.DebugLevel)

	args := &CmdArgs{}
	flag.StringVar(&args.DumpServiceURL, "dump-service-url", globals.PublicDumpServiceURL, "dump service URL")
	flag.StringVar(&args.LookupServiceURL, "lookup-service-url", globals.PublicLookupServiceURL, "lookup service URL")
	flag.Var(&args.Keys, "key", "encryption key")
	flag.StringVar(&args.BlockchainNodeURL, "blockchain-node-url", globals.BlockchainNodeURL, "blockchain node url")
	flag.BoolVar(&args.UseLegacyLookupService, "use-legacy-lookup-service", false, "use legacy lookup service")
	flag.Parse()

	//os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "/Users/regnull/gcloud/clear-talent-299521-9a3e9ed59bf1.json")

	if len(args.Keys) == 0 {
		log.Fatal().Msg("at least one key must be specified")
	}

	var keys []*KeyEntry
	var err error
	keys, err = getKeys(args.Keys)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load keys")
	}

	opts := []grpc.DialOption{
		grpc.WithInsecure(),
		grpc.WithBlock(),
		grpc.WithTimeout(time.Second * 5),
	}

	dumpConn, err := grpc.Dial(args.DumpServiceURL, opts...)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to connect to the dump server")
	}
	defer dumpConn.Close()

	for _, e := range keys {
		p, err := protoutil.IdentityProof(e.PrivateKey, time.Now())
		if err != nil {
			log.Fatal().Err(err).Msg("failed to generate identity proof")
		}
		e.IdentityProof = p
	}

	ctx := context.Background()
	client := pb.NewDMSDumpServiceClient(dumpConn)
	lookupConn, err := grpc.Dial(args.LookupServiceURL, opts...)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to connect to the lookup server")
	}
	defer lookupConn.Close()
	lookupService := pb.NewLookupServiceClient(lookupConn)

	log.Info().Str("url", args.BlockchainNodeURL).Msg("connecting to blockchain node")
	blockchainClient, err := ethclient.Dial(args.BlockchainNodeURL)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to connect to blockchain node")
	}
	blockchain := bc.NewBlockchain(blockchainClient, globals.KeyRegistryContractAddress,
		globals.NameRegistryContractAddress, globals.ConnectorRegistryContractAddress, nil)

	var combinedLookupClient pb.LookupServiceClient
	if args.UseLegacyLookupService {
		log.Info().Msg("using legacy lookup service")
		combinedLookupClient = lookupService
	} else {
		combinedLookupClient = bc.NewLookupServiceClient(blockchain, lookupService, false)
	}

	cache := newscache.New()
	err = cache.Refresh()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to get headlines")
	}

	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		for range ticker.C {
			err := cache.Refresh()
			if err != nil {
				log.Error().Err(err).Msg("error refreshing headlines")
			}
		}
	}()

	ticker := time.NewTicker(5 * time.Second)
	for range ticker.C {
		for _, key := range keys {
			for {
				res, err := client.Receive(ctx, &pb.ReceiveRequest{IdentityProof: key.IdentityProof})
				if err != nil {
					st, ok := status.FromError(err)
					if !ok {
						log.Fatal().Err(err).Msg("error receiving messages")
					}
					if st.Code() == codes.NotFound {
						// This is expected - not new messages.
						break
					}
					log.Fatal().Err(err).Msg("error receiving messages")
				}
				msg := res.GetMessage()

				lookupRes, err := combinedLookupClient.LookupName(ctx, &pb.LookupNameRequest{Name: msg.GetSender()})
				if err != nil {
					log.Fatal().Err(err).Msg("failed to get receiver public key")
				}
				senderKey, err := easyecc.NewPublicFromSerializedCompressed(lookupRes.GetKey())
				if err != nil {
					log.Fatal().Err(err).Msg("invalid receiver public key")
				}

				if !protoutil.VerifySignature(msg.GetSignature(), lookupRes.GetKey(), msg.GetContent()) {
					log.Fatal().Msg("signature verification failed")
				}

				content, err := key.PrivateKey.Decrypt(msg.Content, senderKey)
				if err != nil {
					log.Fatal().Msg("failed to decode message")
				}

				r := bytes.NewReader(filterMalformedHeaders(content))
				e, err := message.Read(r)
				if err != nil {
					log.Error().Err(err).Msg("failed to read message")
					continue
				}
				h := mail.HeaderFromMap(e.Header.Map())
				al, err := h.AddressList("From")
				if err != nil {
					log.Error().Err(err).Msg("failed to get from address")
					continue
				}
				if len(al) != 1 {
					log.Error().Err(err).Msg("more than one address in from address list")
					continue
				}
				to := al[0].Address

				subj, err := h.Subject()
				if err != nil {
					log.Error().Err(err).Msg("failed to get subject")
					continue
				}

				var articleId int64
				if subj != "" {
					articleId, _ = strconv.ParseInt(subj, 10, 32)
				}

				log.Debug().Str("to", to).Msg("got address")
				if articleId != 0 {
					log.Debug().Int("id", int(articleId)).Msg("getting article")
					headline, text, err := cache.GetArticle(int(articleId))
					if err != nil {
						log.Error().Int("id", int(articleId)).Err(err).Msg("error retrieving article")
					} else {
						err = sendArticle(ctx, text, headline, to, key.UbikomName, msg.Sender, key.PrivateKey, lookupService)
						if err != nil {
							log.Error().Int("id", int(articleId)).Err(err).Msg("error sending the article")
						}
					}
					continue
				}
				headlines := cache.GetHeadlines()

				buf := new(bytes.Buffer)
				buf.WriteString(header)
				for _, h := range headlines {
					buf.WriteString(fmt.Sprintf("[%d] %s\n\n", h.ID, h.Title))
				}
				buf.WriteString(footer)

				resp, err := CreateTextEmail(&Email{
					From: &mail.Address{
						Address: fmt.Sprintf("%s@ubikom.cc", key.UbikomName),
					},
					To: []*mail.Address{
						{
							Address: to,
						},
					},
					Subject: headlinesSubject,
					Date:    time.Now(),
					Body:    buf.String(),
				})
				if err != nil {
					log.Error().Err(err).Msg("failed to create email")
				}

				respReceiver := "gateway"
				if msg.Sender != "gateway" {
					respReceiver = msg.Sender
				}

				err = protoutil.SendEmail(ctx, key.PrivateKey, resp, key.UbikomName, respReceiver, lookupService)
				if err != nil {
					log.Error().Err(err).Msg("failed to send response")
				} else {
					log.Info().Str("to", respReceiver).Msg("message sent")
				}
			}
		}
	}
}

func sendArticle(ctx context.Context, text string, headline string, to string, ubikomName string, sender string,
	privateKey *easyecc.PrivateKey, lookupService pb.LookupServiceClient) error {
	respMsg, err := CreateTextEmail(&Email{
		From: &mail.Address{
			Name:    "Ubikom War Info",
			Address: "war-info@ubikom.cc",
		},
		To: []*mail.Address{
			{
				Address: to,
			},
		},
		Subject: headline,
		Date:    time.Now(),
		Body:    text,
	})
	if err != nil {
		return err
	}

	respReceiver := "gateway"
	if sender != "gateway" {
		respReceiver = sender
	}

	err = protoutil.SendEmail(ctx, privateKey, []byte(respMsg), ubikomName, respReceiver, lookupService)
	if err != nil {
		log.Error().Err(err).Msg("failed to send response")
	} else {
		log.Info().Str("to", respReceiver).Msg("message sent")
	}
	return nil
}

func filterMalformedHeaders(body []byte) []byte {
	bodyStr := string(body)
	lines := strings.Split(bodyStr, "\n")
	var newLines []string
	headers := true
	for _, line := range lines {
		if headers && (line == "" || line == "\r") {
			// Done with headers.
			headers = false
		}
		if headers &&
			(strings.HasPrefix(line, ">From") || strings.HasPrefix(line, "From") &&
				!strings.HasPrefix(line, "From:")) {
			continue
		}
		newLines = append(newLines, line)
	}
	newBody := strings.Join(newLines, "\n")
	return []byte(newBody)
}

type Email struct {
	From    *mail.Address
	To      []*mail.Address
	Cc      []*mail.Address
	Subject string
	Date    time.Time
	Body    string
}

func CreateTextEmail(email *Email) ([]byte, error) {
	var h mail.Header
	h.SetDate(email.Date)
	h.Set("Content-Language", "ru")
	h.Set("Content-Type", "text/plain; charset=utf-8; format=flowed")
	h.SetAddressList("From", []*mail.Address{email.From})
	h.SetAddressList("To", email.To)
	if email.Cc != nil {
		h.SetAddressList("Cc", email.Cc)
	}
	h.SetSubject(email.Subject)

	var b bytes.Buffer

	w, err := mail.CreateSingleInlineWriter(&b, h)
	if err != nil {
		return nil, err
	}
	_, err = w.Write([]byte(email.Body))
	if err != nil {
		return nil, err
	}
	w.Close()
	return b.Bytes(), nil
}

func getCurrentExecDir() (dir string, err error) {
	path, err := exec.LookPath(os.Args[0])
	if err != nil {
		fmt.Printf("exec.LookPath(%s), err: %s\n", os.Args[0], err)
		return "", err
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}

	dir = filepath.Dir(absPath)

	return dir, nil
}

func getKeys(keyFiles []string) ([]*KeyEntry, error) {
	for _, f := range keyFiles {
		log.Debug().Str("file", f).Msg("got key file")
	}
	var ret []*KeyEntry
	for _, keyFile := range keyFiles {
		if !path.IsAbs(keyFile) {
			execDir, err := getCurrentExecDir()
			if err != nil {
				return nil, err
			}
			keyFile = path.Join(execDir, keyFile)
		}
		privateKey, err := easyecc.NewPrivateKeyFromFile(keyFile, "")
		if err != nil {
			return nil, err
		}
		n := path.Base(keyFile)
		parts := strings.Split(n, ".")
		if len(parts) != 2 {
			return nil, errors.New("cannot parse key file")
		}
		name := parts[0]
		log.Debug().Str("name", name).Msg("loaded key")
		ret = append(ret, &KeyEntry{PrivateKey: privateKey, UbikomName: name})
	}
	return ret, nil
}
