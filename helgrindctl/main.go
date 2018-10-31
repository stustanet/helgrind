package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"time"
)

// TODO THIS IS BAD - duplicated from config.go
// TODO how to utilize the existing loadconfig stuff?
// struct used to parse the config from the JSON file
type jsonConfigDevice struct {
	Enabled bool
	Name    string
	Sha256  string
}

type jsonConfigUser struct {
	Enabled bool
	Name    string
	Devices []jsonConfigDevice
}

type jsonConfig struct {
	Listen          string
	CaCert          string
	ServerCertChain string
	ServerPrivKey   string
	Services        map[string]struct {
		Enabled bool
		Host    string
		Target  string
		Secret  string
		Users   map[string]jsonConfigUser
	}
}

func openConfig(cfgfile string) *jsonConfig {
	var f *os.File
	var err error

	if f, err = os.Open(cfgfile); err != nil {
		log.Fatal("Could not open config", err)
	}
	jc := new(jsonConfig)
	err = json.NewDecoder(f).Decode(jc)
	f.Close()
	if err != nil {
		log.Fatal("config error", err)
	}

	return jc
}

func updateConfig(cfgfile string, cfg *jsonConfig) {
	// Move the current config to a unique place
	// write a new configfile based on the config in cfg

	newpath := cfgfile + time.Now().Format("2018-12-31_12_00_00")
	os.Rename(cfgfile, newpath)

	data, err := json.MarshalIndent(cfg, "", "    ")
	if err != nil {
		log.Fatal(err)
	}

	err = ioutil.WriteFile(cfgfile, []byte(data), 0644)
	if err != nil {
		log.Fatal("writing config: ", err)
	}
}

func generateCSRConfig(cfgfile, service, alias, name, email, outfile string) {
	cfg := openConfig(cfgfile)
	if service == "" {
		log.Fatal("Specify a service")
	}

	serviceobject, ok := cfg.Services[service]
	if !ok {
		log.Fatal("The service " + service + " does not exist")
	}

	if alias == "" || email == "" {
		log.Fatal("-alias and -email are required")
	}

	if name == "" {
		if user, ok := serviceobject.Users[alias]; ok {
			name = user.Name
		} else {
			log.Fatal("-name is required for a new user")
		}
	}

	csr_config := fmt.Sprintf(
		`prompt = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
countryName = DE
stateOrProvinceName = München
localityName = StuStaNet e.V.
organizationName = %s
organizationalUnitName = %s
commonName = %s
emailAddress = %s
## 1. Generate a key
# openssl genrsa -out client.key 2048
## 2. Take this client.conf and generate a Signing request
# openssl req -new -config client.conf -key client.key -out client.csr
## 3. Send the client.csr to your administrator (telling him to helgrindctl --action sign --csr client.csr --out client.cert)
## 4. the file client.key will NEVER EVER leave your device.
## 5. Receive your certificate client.cert
## 6. Pack your client cert and your private key together for firefox:
# openssl pkcs12 -export -in client.cert -inkey client.key -out authenticate-helgrind.p12
## 7. Install the cert and private key in your firefox: search for "certificate" -> view certificates -> Your Certificates -> [Import]
`,
		service, name, alias, email)

	if outfile == "" {
		print(csr_config)
	} else {
		ioutil.WriteFile(outfile, []byte(csr_config), 0644)
	}
}

func loadCSR(filename string) (csr *x509.CertificateRequest) {

	// Read the CSR and extract the servicename
	bindata, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal("Could not open csr", err)
	}

	// convert PEM encoded openssl cert to DER
	block, _ := pem.Decode(bindata)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		log.Fatal("this is no CSR")
	}

	csr, err = x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		log.Fatal("Could not parse csr", err)
	}
	return
}
func encoded_sha256sum(filename string) (hexSha256 string) {
	// Read back the certificate, to generate the checksum
	// convert PEM encoded openssl cert to DER

	bindata, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal("Could not open cert", err)
	}

	block, _ := pem.Decode(bindata)
	if block == nil || block.Type != "CERTIFICATE" {
		log.Fatal("this is no CSR")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal("Could not parse cert", err)
	}

	shasum := sha256.Sum256(cert.Raw)
	hexSha256 = hex.EncodeToString(shasum[:])
	return
}

func generateAndApplyCert(cfgfile, csr, device, outfile string) {
	cfg := openConfig(cfgfile)

	if csr == "" {
		log.Fatal("-csr is required")
	}
	if outfile == "" {
		log.Fatal("-out ist required")
	}

	csrdata := loadCSR(csr)

	// grab the service, and the user-alias from the csr
	csr_service := csrdata.Subject.Organization[0]
	csr_name := csrdata.Subject.OrganizationalUnit[0]
	csr_alias := csrdata.Subject.CommonName

	service, ok := cfg.Services[csr_service]
	if !ok {
		log.Fatal("Service ", csr_service, " not found")
	}
	user, user_exists := service.Users[csr_alias]

	if !user_exists {
		fmt.Printf("Applying \033[1mNEW\033[0m user \033[033m%s\033[0m to service \033[022m%s\033[0m\n",
			csr_alias, csr_service)
	} else {
		fmt.Printf("Add new key of existing user \033[033m%s\033[0m to service \033[022m%s\033[0m\n",
			user.Name, csr_service)
	}

	if device == "" {
		// The device name could be included in the certificate - but that would
		// mean that the config generated here could not be reused - this way
		// it can be ensured, that the devicename has a seperate source of trust.
		print("Please enter the device name for this key, or CTRL+C to cancel\n")
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		device = scanner.Text()
	}

	cmd := exec.Command("openssl", "x509", "-req",
		"-in", csr,
		"-CA", cfg.CaCert,
		"-CAkey", cfg.ServerPrivKey,
		"-CAcreateserial",
		"-days", "35600",
		"-out", outfile,
	)

	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		log.Println("openssl subrocess failed:")
		log.Printf("command: %v\n", cmd.Args)
		log.Println(string(stdoutStderr))
		log.Fatal("Error: ", err)
	}

	new_device := jsonConfigDevice{
		Enabled: true,
		Name:    device,
		Sha256:  encoded_sha256sum(outfile)}

	// Prepare the config to be written back
	if !user_exists {
		user = jsonConfigUser{
			true,
			csr_name,
			[]jsonConfigDevice{new_device},
		}
		service.Users[csr_alias] = user
	} else {
		user.Devices = append(user.Devices, new_device)
		service.Users[csr_alias] = user
	}

	updateConfig(cfgfile, cfg)
	print_service(csr_service, cfg)
}

func print_service(name string, cfg *jsonConfig) {
	serv, ok := cfg.Services[name]
	if !ok {
		log.Fatal("Service ", name, "not found")
	}

	print("\033[1mService: ", name, "\033[0m\n")
	if !serv.Enabled {
		print("\tDISABLED\n")
	}
	print("\tHost: ", serv.Host, "\n")
	print("\tTarget: ", serv.Target, "\n")
	print("\tUsers:\n")
	print("\t\tUser\tDevices\n")
	for username, user := range serv.Users {
		if !user.Enabled {
			print("\t\t\033[9m", username, "\033[0m\n")
		} else {
			print("\t\t\033[1m", username, "\033[0m\t")
			for id, dev := range user.Devices {
				if id != 0 {
					print(", ")
				}
				if dev.Enabled {
					print(dev.Name)
				} else {
					print("\033[9m", dev.Name, "\033[0m")
				}
			}
			print("\n")
		}
	}
}

func list(cfgfile, service string) {
	cfg := openConfig(cfgfile)

	if service == "" {
		for name, _ := range cfg.Services {
			print_service(name, cfg)
		}
	} else {
		print_service(service, cfg)
	}
}

func revoke(cfgfile, servicename, alias, device string) {
	cfg := openConfig(cfgfile)

	if servicename == "" || alias == "" {
		log.Fatal("-service and -alias are required")
	}

	serv, ok := cfg.Services[servicename]
	if !ok {
		log.Fatal("Service ", servicename, "not found")
	}

	user, ok := serv.Users[alias]
	if !ok {
		log.Fatal("Service does not have a user named ", alias)
	}

	if device == "" {
		log.Printf("Disabling the whole user %s", alias)
		// TODO request confirmation?
		user.Enabled = false
	} else {
		found := false
		for idx, dev := range user.Devices {
			if dev.Name == device {
				log.Printf("Disabling device %s of user %s\n", dev.Name, user.Name)
				user.Devices[idx].Enabled = false
				found = true
			}
		}
		if !found {
			log.Fatal("Device ", device, " not found for user ", user.Name)
		}
	}

	serv.Users[alias] = user

	print_service(servicename, cfg)
	// If a confirmation is neccessary before disabling enable this.
	// I think it is useless, because it is only setting a flag.
	/*print("please confirm the changes with a uppercase yes. CTRL+C to cancel\n")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	if "YES" != scanner.Text() {
		log.Fatal("Not doing anything")
	}*/

	updateConfig(cfgfile, cfg)
}

func reenable(cfgfile, servicename, alias, device string) {
	cfg := openConfig(cfgfile)

	if servicename == "" || alias == "" {
		log.Fatal("-service and -alias are required")
	}

	serv, ok := cfg.Services[servicename]
	if !ok {
		log.Fatal("Service ", servicename, "not found")
	}

	user, ok := serv.Users[alias]
	if !ok {
		log.Fatal("Service does not have a user named ", alias)
	}

	if device == "" {
		log.Printf("Disabling the whole user %s", alias)
		// TODO request confirmation?
		user.Enabled = false
	} else {
		found := false
		for idx, dev := range user.Devices {
			if dev.Name == device {
				log.Printf("Reenabling device %s of user %s\n", dev.Name, user.Name)
				user.Devices[idx].Enabled = true
				found = true
			}
		}
		if !found {
			log.Fatal("Device ", device, " not found for user ", user.Name)
		}
	}

	serv.Users[alias] = user

	print_service(servicename, cfg)
	updateConfig(cfgfile, cfg)
}

func main() {
	var cfgfile, action, service, email, csr, name, out, alias, device string

	flag.StringVar(&cfgfile, "cfg", "/etc/helgrind.json", "path of the config file")
	flag.StringVar(&action, "action", "help", "Action to take")
	flag.StringVar(&service, "service", "", "Service")
	flag.StringVar(&device, "device", "", "Devicename")
	flag.StringVar(&alias, "alias", "", "User alias")
	flag.StringVar(&name, "name", "", "Full user name")
	flag.StringVar(&email, "email", "", "User email")
	flag.StringVar(&csr, "csr", "", "Certificate signing request file")
	flag.StringVar(&out, "out", "", "File to save to")
	flag.Parse()

	switch action {
	case "config":
		generateCSRConfig(cfgfile, service, alias, name, email, out)
	case "apply":
		generateAndApplyCert(cfgfile, csr, device, out)
	case "list":
		list(cfgfile, service)
	case "revoke":
		revoke(cfgfile, service, alias, device)
	case "reenable":
		reenable(cfgfile, service, alias, device)
	default:
		print("Available Actions: \n")
		print("  config -cfg [] -service [] -alias [] -name [] -email [] [-out []]\n")
		print("  apply -cfg [] -csr [] [-device []]\n")
		print("  list -cfg [] [-service []]\n")
		print("  revoke -cfg [] -alias [] [-device []]\n")
		print("  reenable -cfg [] -alias [] [-device []]\n")
	}
}
