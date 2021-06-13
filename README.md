# 2FA toolkit for Bash scripting

### Features

- HMAC
- HOTP
- TOTP
- QR-code

### Requirements

- bash
- openssl
- python3 (only if URI / QR-code is required)
- [qrencode](https://github.com/fukuchi/libqrencode) (only if QR-code is required. For *Ubuntu*, `sudo apt install qrencode` would install it)

### Manual

Source the library in Bash with `source 2fa.bash` to avail the functions defined therein. The API definitions can be found within the script.

### License

GNU GPL v3 or later

Copyright (C) Somajit Dey 2021