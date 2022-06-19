## ESS service access components
The ESS service can be accessed using two components
* `ess_admin` tool - used by `admin` users to manage users
* `libess` - used by users to authenticate from PAM linux module

### The `ess_admin` tool
#### TLS certificates
In order to connect to the ESS service the admin clients must use the proper TSL certificates which can be set from:
1. from command line
2. using the envars: `ESS_ADMIN_ROOT_CA`, `ESS_ADMIN_CERT` and `ESS_ADMIN_CERT_KEY`
3. the last option is the `./cert/admin` folder from current working directory
In order to get the admin certificate use this [guide](https://github.com/catalin-h/ess_backend#getting-the-adminpam-client-service-root-ca-and-client-certificates)

#### Tool command line interface
USAGE:

    ess_admin [OPTIONS] <SUBCOMMAND>

OPTIONS:

        --pam                This flag controls if we need to connect as PAM user. By default the
        --cafile <CAFILE>    Root CA file path To skip this required args set ESS_ROOT_CA envar
        --cert <CERT>        The admin client certificate file path To skip this required args set
                             ESS_ADMIN_CERT envar
        --key <KEY>          The admin client certificate private key file path To skip this
                             required args set ESS_ADMIN_CERT_KEY envar
                             admin connection details will be used
        --url <URL>          The webservice host url To skip this required args set ESS_WS_URL envar
    -v, --verbose            Verbose mode
    -V, --version            Print version information
    -h, --help               Print help information

SUBCOMMANDS:

    add         Insert user
    delete      Delete user
    get-all     Get all users
    get-user    Get user data by username
    help        Print this message or the help of the given subcommand(s)
    update      Update user info & secret except the username
    verify      Verify secret for username

##### Add user
USAGE:

    ess_admin add [OPTIONS] --username <USERNAME>

OPTIONS:

    -f, --first-name <FIRST_NAME>    The user's first name [default: noname]
    -l, --last-name <LAST_NAME>      The user's last name [default: noname]
    -q, --qr-code                    Return plain secret code or as QR code
    -u, --username <USERNAME>        The unique user name

##### Delete user
USAGE:

    ess_admin delete <USERNAME>

ARGS:

    <USERNAME>    The unique username

##### Update user info
USAGE:

    ess_admin update [OPTIONS] <USERNAME>

ARGS:

	<USERNAME>    The unique user name

OPTIONS:

    -f, --first-name <FIRST_NAME>    The user's first name
    -l, --last-name <LAST_NAME>      The user's last name

##### Show user data
USAGE:

    ess_admin get-user <USERNAME>

ARGS:

    <USERNAME>    The unique username

##### Show all user data
USAGE:

    ess_admin get-all

##### Verify one time password for username
USAGE:

    ess_admin verify <USERNAME> <ONE_TIME_PASSWORD>

ARGS:

    <USERNAME>             The unique user name
    <ONE_TIME_PASSWORD>    The OTP code generated by the app

### The `ess` PAM library API

#### TLS certificates
In order to connect to the ESS service the PAM clients must use the proper TSL certificates which can be set from:
1. using the envars: `ESS_PAM_ROOT_CA`, `ESS_PAM_CERT` and `ESS_PAM_CERT_KEY`
2. or using the `./cert/pam` folder from current working directory
In order to get the PAM client certificate use this [guide](https://github.com/catalin-h/ess_backend#getting-the-adminpam-client-service-root-ca-and-client-certificates)

#### The current `ess` library API
##### Verify the one time password for user name
```
int verify_otp(const char *username, const char *otp);
```
The function returns `ESS_OK` or `0` on success and `ESS_ERROR` or non-zero value in case of an error.

##### Get the last API call error
```
const char *ess_pam_last_error_str(void);
```
This function should be called only if the `ESS PAM` API returned `ESS_ERROR` or other non-zero value.
If the last call succeeded the last error will be reset to `"ok"` string.

##### Get the ESS API version
```
const char *ess_pam_version(void);
```

### How to build and install the components
To build the components must have the cargo & rust compiler installed on the build machine.
```
cargo build --release
```
Note that the ess API header `esspam.h` will be generated by the cargo build.

#### Running the tests
```
cargo tests -- --nocapture
```
#### To install the `ess_admin` tool for current user
```
cargo install --path .
```
The preview command will install the tool in `/home/<username>/.cargo/bin/`.
Since the certificates must not be shared they can be installed in $HOME and
set the `ESS_ADMIN_ROOT_CA`, `ESS_ADMIN_CERT` and `ESS_ADMIN_CERT_KEY` envars
from .bashrc.

#### The PAM access library
TBD
