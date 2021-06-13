# HOTP(RFC-4226) and TOTP(RFC-6238) implementation
# Compare with Google Authenticator, FreeOTP, Microsoft Authenticator
# Source: . ./2fa.bash

hmac(){
  # Usage: hmac <key in hex> <data to be hashed in hex>
  local key="${1}"
  local data="${2}"
  echo -n "${data}" | xxd -r -p | openssl dgst -sha1 -mac hmac -macopt hexkey:"${key}" | cut -d ' ' -f 2
}; export -f hmac

keygen(){
  # Generate random 160-bit keys in base32
  local rand; read rand </dev/urandom
  key=$(RANDOM="${EPOCHSECONDS}"; printf "%x" "${RANDOM}") # Seeding with current time
  hmac "${key}" "${rand}_${SECONDS}" | xxd -r -p | base32
}; export -f keygen

hotp(){
  # Ref: RFC-4226
  # Usage: hotp <key or secret in base32> <counter>
  local key_hex=$(echo -n "${1}" | base32 -d | xxd -p)
  local counter_hex="$(printf %016x "${2}")" # Get 64 bit hex representation of the int counter
  # Now, simply follow Sec. 5.3 of RFC-4226
  local string=$(hmac "${key_hex}" "${counter_hex}")
  local -i offset=$((0x${string:39:1}))
  local truncated=${string:2*offset:8}
  local masked=$((0x${truncated} & 0x7fffffff))
  printf "%06d\n" $((masked % 1000000))
}; export -f hotp

totp(){
  # Ref: RFC-6238
  # Usage: totp <key or secret in base32> [<unix time>]
  # If no unix timestamp is passed as parameter, it defaults to current time
  timestamp=${2:-"${EPOCHSECONDS}"}
  hotp "${1}" "$((timestamp/30))"
}; export -f totp

uri_qr(){
  # Generate shareable URI and QR-code for a base32 secret or key
  # Ref: https://github.com/google/google-authenticator/wiki/Key-Uri-Format
  # Usage: uri_qr [-c <initial counter for HOTP>] [-i issuer] [-u user] [-o path] key
  # If -c option is absent, TOTP is chosen
  local OPTIND=1
  local auth="totp"
  local counter=
  local issuer="Issuer"
  local user="User@email.tld"
  local qr_path="qrcode.png"
  urlencode(){ python3 -c "import urllib.parse as ul; print(ul.quote_plus('$1'))";}
  export -f urlencode
  while getopts c:i:u:o: opt; do
    case "${opt}" in
      c)
        auth="hotp"
        counter="&counter=${OPTARG}"
        ;;
      i)
        issuer="$(urlencode "${OPTARG}")"
        ;;
      u)
        user="$(urlencode "${OPTARG}")"
        ;;
      o)
        qr_path="${OPTARG}"
        ;;
      *)
        return 1
        ;;
    esac
  done
  uri="otpauth://${auth}/${issuer}:${user}?secret=${!OPTIND}&issuer=${issuer}${counter}"
  echo "${uri}"
  command -v qrencode &>/dev/null && qrencode -o "${qr_path}" "${uri}"
}; export uri_qr