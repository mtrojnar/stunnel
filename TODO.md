# stunnel TODO


### High priority features
These features will likely be supported some day.
A sponsor could allocate my time to get them faster.

* Add client certificate autoselection based on the list of accepted issuers:
  SSL_CTX_set_client_cert_cb(), SSL_get_client_CA_list().
* Add an Apparmor profile.
* Optional line-buffering of the log file.
* Log rotation on Windows.
* Configuration file option to limit the number of concurrent connections.
* Command-line server control interface on both Unix and Windows.
* Separate GUI process running as the current user on Windows.
* An Android GUI.
* OCSP stapling (tlsext_status).
* Indirect CRL support (RFC 3280, section 5).
* MSI installer for Windows.

### Low priority features
These features will unlikely ever be supported.

* Database and/or directory interface for retrieving PSK secrets.
* Support static FIPS-enabled builds.
* Service-level logging destination.
* Logging to NT EventLog on Windows.
* Internationalization of logged messages (i18n).
* Generic scripting engine instead or static protocol.c.
* Add 'leastconn' failover strategy to order defined 'connect' targets
  by the number of active connections.
* Add '-status' command line option reporting the number of clients
  connected to each service.

### Rejected features
Features I will not support, unless convinced otherwise by a wealthy sponsor.

* Support for adding X-Forwarded-For to HTTP request headers.
  This feature is less useful since PROXY protocol support is available.
* Support for adding X-Forwarded-For to SMTP email headers.
  This feature is most likely to be implemented as a separate proxy.
* Additional certificate checks (including wildcard comparison) based on:
  - O (Organization), and
  - OU (Organizational Unit).
* Set processes title that appear on the ps(1) and top(1) commands.
  I could not find a portable *and* non-copyleft library for it.
