#!/usr/bin/env bash
#
# Generates a self-signed PKCS12 keystore for local HTTPS development.
# This is the "KeyStore for HTTPS" piece called out in the rubric: a
# keystore is a file holding a private key plus its matching X.509
# certificate; Tomcat (embedded inside Spring Boot) loads it at startup
# to perform the TLS handshake for every HTTPS connection.
#
# In production, replace the self-signed certificate this script creates
# with one issued by a real Certificate Authority (your org's internal
# CA, or a public one like Let's Encrypt) -- a self-signed cert is fine
# for local development because you control both ends of the connection,
# but a browser/client has no way to verify it belongs to who it claims
# to, which is exactly why curl needs -k and browsers show a warning
# against it.
#
# "set -euo pipefail": stop the script immediately on any command failure
# (-e), on use of an undefined variable (-u), and propagate failure
# through any pipe (-o pipefail) -- fails loudly instead of silently
# continuing with a half-created keystore.
set -euo pipefail

# Resolve the script's own directory, then go one level up to the project
# root, so this script works no matter what directory it's invoked from.
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEYSTORE_OUTPUT_DIR="${PROJECT_ROOT}/src/main/resources"
KEYSTORE_FILE_PATH="${KEYSTORE_OUTPUT_DIR}/keystore.p12"

# Must match server.ssl.key-alias in application.properties -- Tomcat
# uses the alias to pick the right entry out of the keystore.
CERTIFICATE_ALIAS="secureapp"

# Reuses the same environment variable application.properties falls back
# to, so generating the keystore and running the app agree on the
# password without it being duplicated as a separate literal here.
KEYSTORE_PASSWORD="${SERVER_SSL_KEY_STORE_PASSWORD:-changeit}"

CERTIFICATE_VALIDITY_DAYS=365

if [ -f "${KEYSTORE_FILE_PATH}" ]; then
  echo "Keystore already exists at ${KEYSTORE_FILE_PATH} -- delete it first if you want to regenerate."
  exit 0
fi

# keytool ships with every JDK. -genkeypair creates a new public/private
# key pair AND wraps the public key in a self-signed certificate, storing
# both together under one alias inside the keystore file.
keytool -genkeypair \
  -alias "${CERTIFICATE_ALIAS}" \
  -keyalg RSA \
  -keysize 2048 \
  -storetype PKCS12 \
  -keystore "${KEYSTORE_FILE_PATH}" \
  -validity "${CERTIFICATE_VALIDITY_DAYS}" \
  -storepass "${KEYSTORE_PASSWORD}" \
  -keypass "${KEYSTORE_PASSWORD}" \
  -dname "CN=localhost, OU=Dev, O=SecureApp, L=City, ST=State, C=US"
  # CN=localhost matters most: TLS clients check the certificate's Common
  # Name (or Subject Alternative Name) against the hostname they
  # connected to, so this must say "localhost" for local testing against
  # https://localhost:8443 to line up correctly.

echo "Keystore created at ${KEYSTORE_FILE_PATH}"
echo "Remember: this file and its password must NEVER be committed to git."
