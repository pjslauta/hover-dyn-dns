# Hover DNS Update Script

This project is a Python script for updating DNS records on Hover. It supports optional logging, TOTP-based 2FA, and the use of `mitmproxy` for debugging HTTP/HTTPS requests.

## Dependencies

- Python 3.x
- `requests` library
- `mitmproxy` (optional, for debugging)

## Setup Instructions

### 1. Clone the Repository

```sh
git clone <repository_url>
cd <repository_directory>
```

### 2. Install Python Dependencies

Install the required Python libraries using `pip`:

```sh
pip install requests
```

### 3. Install `mitmproxy` (Optional)

`mitmproxy` is used for debugging HTTP/HTTPS requests. To install `mitmproxy`, run:

```sh
pip install mitmproxy
```

### 4. Create Configuration Files

Create the following configuration files:

#### `config.json`

Create a `config.json` file in the project directory with the following content:

```json
{
    "dnsid": "<your_dns_id>",
    "username": "<your_hover_username>",
    "password": "<your_hover_password>",
    "discoverip": "true",
    "srcdomain": "this.example.com",
    "ipaddress": "192.168.1.1",
    "totp_secret": "<your_totp_secret>",
    "logLevel": "info",
    "nakedDomain": "example.com",
    "logRetentionMaxDays": "7",
    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
}
```

- `dnsid`: The DNS record ID to update.
- `username`: Your Hover account username.
- `password`: Your Hover account password.
- `discoverip`: Set to `"true"` to auto-discover your public IP.
- `srcdomain`: The subdomain to update (e.g., `"this.example.com"`).
- `ipaddress`: The IP address to set (overrides `discoverip` if provided).
- `totp_secret`: Your TOTP secret for 2FA (if enabled on your Hover account).
- `logLevel`: Logging level (`"info"`, `"debug"`, etc.).
- `nakedDomain`: The root domain (e.g., `"example.com"`).
- `logRetentionMaxDays`: How many days to keep log files.
- `userAgent`: The User-Agent string to use for HTTP requests.

Replace the placeholders with your actual values.

#### `IP`

Create an empty `IP` file in the project directory:

```sh
type nul > IP
```
*(On Linux/macOS: `touch IP`)*

## Usage Instructions

### Running the Script

To run the script, use the following commands:

#### Install prerequisites:
```sh
pip install -r requirements.txt
```

#### Run the script:

```sh
python hover-update.py [--loglevel LEVEL] [--mitm] [--nocerts] [--getDNSID] [--getDomains] [--interval SECONDS]
```

### Command Line Arguments

- `--loglevel LEVEL`: Set log level (DEBUG, INFO, WARNING, ERROR, CRITICAL). Overrides config.json log level. Default is INFO.
- `--mitm`: Route HTTP/HTTPS requests through `mitmproxy` for debugging.
- `--nocerts`: Disable certificate verification for mitmproxy.
- `--getDNSID`: Get DNS IDs for all domains in the account.
- `--getDomains`: Get all domains in the account.
- `--interval SECONDS`: Run at a specified interval (in seconds). Overrides config value `runInterval`.
- `--config PATH`: Path to configuration file (default: `config.json`).

### Example

To run the script with a custom config file:

```sh
python hover-update.py --config myconfig.json
```

To run the script with logging enabled:

```sh
python hover-update.py --loglevel INFO
```

To run the script with `mitmproxy` enabled:

```sh
python hover-update.py --mitm
```

To run the script with both logging and `mitmproxy` enabled:

```sh
python hover-update.py --loglevel DEBUG --mitm
```

To get DNS IDs for all domains:

```sh
python hover-update.py --getDNSID
```

To get all domains:

```sh
python hover-update.py --getDomains
```

To run the script every 10 minutes:

```sh
python hover-update.py --interval 600
```

## Using `mitmproxy` for Debugging

`mitmproxy` is a powerful tool for debugging HTTP/HTTPS requests. Follow these steps to use `mitmproxy` with this script:

The script is designed to run on Windows or Linux unchanged and will look for the mitmproxy certificates in the appropriate default location for that platform.

### 1. Start `mitmproxy`

Start `mitmproxy` in your terminal:

```sh
mitmproxy
```
This will start `mitmproxy` and listen on port 8080 by default.

### 2. Run the Script with `mitmproxy` Enabled

Run the script with the `--mitm` flag to route HTTP/HTTPS requests through `mitmproxy`:

```sh
python hover-update.py --mitm
```

### 3. Inspect Requests and Responses

In the `mitmproxy` interface, you can inspect the HTTP/HTTPS requests and responses being made by the script. This is useful for debugging and understanding the interactions with the Hover API.

## File Structure

- `hover-update.py`: Main script for updating DNS records on Hover.
- `totp.py`: Contains the TOTP generation function.
- `config.json`: Configuration file with user credentials and settings.
- `IP`: File to store the last known IP address (automatically generated when the IP is resolved).
- `hover-update.log`: Log file (created automatically if logging is enabled).

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on GitHub.

## Contact

For any questions or issues, please contact [pj@code-geeks.com](mailto:pj@code-geeks.com).