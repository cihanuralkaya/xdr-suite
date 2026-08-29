// Command adminseed, bir yönetici için Argon2id parola hash'i üretir ve
// admins tablosu için hazır bir INSERT SQL basar.
//
//	go run ./tools/adminseed -email admin@sirket.local -password "GucluParola!" -role ADMIN -name "IT Admin"
//
// Çıktı PHC-string biçimindedir ve server/internal/security.VerifyPassword ile
// uyumludur (parametreler hash string'inden okunur).
package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"log"

	"golang.org/x/crypto/argon2"
)

func main() {
	email := flag.String("email", "", "yönetici e-postası")
	password := flag.String("password", "", "parola")
	role := flag.String("role", "ADMIN", "rol: VIEWER | OPERATOR | ADMIN")
	name := flag.String("name", "", "görünen ad")
	flag.Parse()

	if *email == "" || *password == "" {
		log.Fatal("-email ve -password zorunlu")
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		log.Fatal(err)
	}
	const (
		time    = 1
		memory  = 64 * 1024
		threads = 4
		keyLen  = 32
	)
	hash := argon2.IDKey([]byte(*password), salt, time, memory, threads, keyLen)
	phc := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memory, time, threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)

	fmt.Println("admins INSERT:")
	fmt.Printf("INSERT INTO admins (email, display_name, role, password_hash)\n")
	fmt.Printf("VALUES ('%s', '%s', '%s', '%s');\n", *email, *name, *role, phc)
}
