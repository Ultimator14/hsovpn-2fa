# HSO VPN 2FA 

This project contains a simple python script to complete the 2FA VPN auth flow for the
Hochschule Offenburg.

It retrieves a sso cookie that can be used by openconnect to establish a vpn connection.
Although openconnect supports a variety of ways to retrieve the sso cookie, it doesn't
provide a convenient way to enter the token manually. With some small modifications to
the openconnect project, this feature can be added.

## Setup

### Clone this repo

For start, clone this repo.

```bash
# Clone the repo
git clone https://github.com/Ultimator14/hsovpn-2fa
cd hsovpn-2fa
```

### Building openconnect

The next step is to build a patched version of openconnect.
The project comes with some dependencies that must be installed first
(libxml, zlib, openssl, pkgconfig). For more information
see [here](https://www.infradead.org/openconnect/building.html).

#### Install dependencies

```bash
# Ubuntu
apt install -y libxml2 zlib1g-dev git python3 python3-pip openssl pkg-config build-essential autotools-dev automake libtool vpnc libssl-dev libxml2-dev python3.10-venv

#Macos
brew install automake
wget https://gitlab.com/openconnect/vpnc-scripts/raw/master/vpnc-script
mkdir /etc/vpnc/ && mv vpnc-script /etc/vpnc/vpnc-script
chmod +x /etc/vpnc/vpnc-script
```

#### Build

```bash
# Download openconnect
git submodule update --init --recursive

cd openconnect

# Patch the source code with the patch in this repo
git apply ../openconnect.patch

# Build openconnect
./autogen.sh
./configure
make
cd ..
```

#### Install

You can use the openconnect binary directly from the build directory. There is no need to install.
However if you want to install into `/usr/local/`, you can do so with `make install`.

Note: The openconnect library will be installed into `/usr/local/lib`, which is not in the `LD_LIBRARY_PATH` for some systems.
If you get errors like this

```
openconnect: error while loading shared libraries: libopenconnect.so.5: cannot open shared object file: No such file or directory
```

then try adding the directory to the library path with

```
export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/usr/local/lib"
```

### Installing python dependencies

Third, install the required python dependencies. We use a virtual environment here.

```bash
# Create virtualenv
python3 -m venv venv
# Install requirements
./venv/bin/activate
pip install -r requirements.txt
```

## Configuration

The script needs some configuration to work. This is done in `secrets.json`.

Add the patched version of openconnect to the `openconnect.executable` if not installed.

### Credentials

It's required that you enable 2FA authentication for your HS account and setup
a TOTP secret. Then add your credentials (`username`, `password`) as well as the TOTP
secret (`totp`) to the `secrets.json` file. You can omit the totp secret. That way
you will be prompted to enter your 6 digit TOTP pin instead.

### VPN config

The parameters `login-url` and `sso-cookie-name` should already be set to the
correct value. If you want to adapt the script to another 2FA flow, you can
determine these values by making an openconnect request like this (adapt `authgroup`
to your needs).

```bash
openconnect -vvv --dump-http-traffic --authgroup=5 --protocol=anyconnect --useragent="AnyConnect" vpn.hs-offenburg.de
```

The result should contain `login-url` and `sso-cookie-name` in the form
```
...
< <sso-v2-login>https://vpn.hs-offenburg.de/+CSCOE+/saml/sp/login?tgname=2FA-Group&#x26;acsamlcap=v2</sso-v2-login>
...
< <sso-v2-token-cookie-name>acSamlv2Token</sso-v2-token-cookie-name>
...
```

### Running openconnect

The script can be configured to directly run openconnect with the correct parameters.
This is done in the `openconnect` section of `secrets.json`. It contains prefix and
suffix of the openconnect command as well as the domain to connect to and the openconnect
executable name/path. The openconnect call with the predefined values is equivalent to

```bash
sudo openconnect \
    --protocol=anyconnect \
    --useragent=AnyConnect \
    --token-mode=anyconnect-sso \
    --token-secret=SECRET_COOKIE_VALUE_HERE \
    vpn.hs-offenburg.de \
    --authgroup=2 \
    -vvv --dump-http-traffic \
```

Note that openconnect must be in `PATH` with the default settings. A custom openconnect binary can be specified via the `executable` option.

You can remove the `openconnect` key from the `secrets.json` file to disable the direct
invocation of openconnect. The script will then only output the sso-cookie.

### Debugging

If the authentication doesn't work, you can enable the `debug` option. This will dump the
contents of the intermediate pages visited during the 2FA procedure. It will also output
more information. Don't use this during every-day usage. It will print your credentials.
