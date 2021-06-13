# HOTP(RFC-4226) and TOTP(RFC-6238) implementation
# Compare with Google Authenticator, FreeOTP, Microsoft Authenticator
# Source: . ./2fa.bash

hmac(){
  # Usage: hmac <key in hex> <data to be hashed in hex>
  # The data can also be provided through stdin if not passed as parameter
  local key="${1}"
  local data="${2}"
  [[ -n "${data}" ]] || read -rd '' data
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
  # Usage: uri_qr [-c <initial counter for HOTP>] [-i issuer] [-u user] [-o path] <secret or key in base32>
  # If -c option is absent, TOTP is chosen
  # The secret or key can also be provided through stdin if not passed as parameter
  # Example: keygen | uri_qr -i Example -u user@example.com
  local OPTIND=1
  local auth="totp"
  local counter=
  local issuer="Issuer"
  local user="User@email.tld"
  local qr_path="qrcode.png"
  urlencode(){ python3 -c "import urllib.parse as ul; print(ul.quote_plus('$1'))";}
  export -f urlencode
  local opt
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
  local secret="${!OPTIND}"
  [[ -n "${secret}" ]] || read -rd '' secret
  uri="otpauth://${auth}/${issuer}:${user}?secret=${secret}&issuer=${issuer}${counter}"
  echo "${uri}"
  command -v qrencode &>/dev/null && qrencode -o "${qr_path}" "${uri}" && echo "${qr_path}" >&2
}; export uri_qr

validate(){
  # Validate a given TOTP for a given secret key in base32 and a time window
  # Env variable:
  #   VAL_WIN - stores validation window in s if set
  #   VAL_SEC - stores validation secret in base32 if set
  # Usage: validate [-w <window in s>] [-s|-k secret] [-q] <TOTP>
  # -q denotes quiet mode
  # If key is not passed as an option it would be read from stdin.
  # -w option overrides VAL_WIN. Default window=60s
  # Exit code: 0/1
  local window="${VAL_WIN:-60}"
  local secret="${VAL_SEC}"
  local OPTIND=1
  local opt quiet_mode
  while getopts w:s:k:q opt; do
    case "${opt}" in
    w) window="${OPTARG}";;
    s|k) secret="${OPTARG}";;
    q) quiet_mode=true;;
    *) return 1;;
    esac
  done
  [[ -n "${secret}" ]] || read -rd '' secret
  local totp_given="${!OPTIND}"
  local timestamp=$((EPOCHSECONDS-window))
  while ((timestamp < EPOCHSECONDS+30)); do
    local totp_gen=$(totp ${secret} ${timestamp})
    if [[ ${totp_gen} == ${totp_given} ]]; then
      [[ -n "${quiet_mode}" ]] || echo Success
      return 0
    else
      ((timestamp+=30))
    fi
  done
  [[ -n "${quiet_mode}" ]] || echo Failure >&2
  return 1
}; export -f validate
