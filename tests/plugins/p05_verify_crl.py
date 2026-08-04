"""stunnel server tests"""

import logging
import pathlib
from plugin_collection import Plugin, ERR_CONN_RESET
from maketest import (
    Config,
    ExpectedConfigurationFailure,
    StunnelAcceptConnect
)


SUCCESS_FAILURE_EVENTS = [
    "peer did not return a certificate",
    "bad certificate",
    "certificate verify failed",
    "unsupported protocol",
    "TLS accepted: previous session reused",
    "Redirecting connection",
    ERR_CONN_RESET,
    "Connection lost",
    "Client received unexpected message",
    "Server received unexpected message",
    "Something went wrong",
    "INTERNAL ERROR"
]

VERIFY_FAILURE_EVENTS = [
    "peer did not return a certificate",
    "bad certificate",
    "unsupported protocol",
    "TLS accepted: previous session reused",
    "Redirecting connection",
    "Client received unexpected message",
    "Server received unexpected message",
    "Something went wrong",
    "INTERNAL ERROR"
]

CONFIG_FAILURE_EVENTS = [
    "peer did not return a certificate",
    "bad certificate",
    "certificate verify failed",
    "unsupported protocol",
    "TLS accepted: previous session reused",
    "Redirecting connection",
    ERR_CONN_RESET,
    "Connection lost",
    "Client received unexpected message",
    "Server received unexpected message",
    "Something went wrong",
    "INTERNAL ERROR"
]


class StunnelTest(StunnelAcceptConnect):
    """Base class for stunnel server tests."""

    crl_file = "CACertCRL.pem"
    crl_check_chain = False
    crl_check_chain_default = False
    verify_chain = True
    verify_peer = False

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.ssl_client = True
        self.params.context = 'load_correct_cert'
        self.params.services = ['server']


    def verification_options(self, cfg: Config) -> str:
        """Return verification options for the stunnel server."""
        lines = []
        if self.verify_chain:
            lines.append("verifyChain = yes")
        if self.verify_peer:
            lines.append("verifyPeer = yes")
        lines.append(f"CAfile = {cfg.certdir}/CACert.pem")
        if self.crl_file:
            lines.append(f"CRLfile = {cfg.certdir}/{self.crl_file}")
        if self.crl_check_chain and not self.crl_check_chain_default:
            lines.append("CRLcheckChain = yes")
        return "\n".join(f"    {line}" for line in lines)


    async def prepare_server_cfgfile(
        self, cfg: Config, port: int, service: str
    ) -> pathlib.Path:
        """Create a configuration file for a stunnel server."""
        default_options = ""
        if self.crl_check_chain_default:
            default_options = "\n    CRLcheckChain = yes\n"
        contents = f"""
    foreground = yes
    debug = debug
    syslog = no
{default_options}
    [{service}]
    accept = 127.0.0.1:0
    connect = 127.0.0.1:{port}
    cert = {cfg.certdir}/server_cert.pem
{self.verification_options(cfg)}
    """
        cfgfile = cfg.tempd / "stunnel_server.conf"
        cfgfile.write_text(contents, encoding="UTF-8")
        return cfgfile


class ExpectedCRLConfigurationFailure(ExpectedConfigurationFailure, StunnelTest):
    """Base class for expected CRL configuration failures."""


class VerifyCRL(StunnelTest):
    """Checking if a CRL accepts a valid leaf certificate.
       The verifyChain option verifies the peer certificate starting from the root CA.
       The self-signed root CA certificate is stored in the file specified with CAfile.
       Certificate Revocation Lists file is stored in the file specified with CRLfile.
       The success is expected because python client presents the valid certificate.
    """

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '051. CRL file with valid certificate'
        self.events.failure = SUCCESS_FAILURE_EVENTS


class FailureVerifyCRL(StunnelTest):
    """Checking if a CRL rejects a revoked leaf certificate.
       The verifyChain option verifies the peer certificate starting from the root CA.
       The self-signed root CA certificate is stored in the file specified with CAfile.
       Certificate Revocation Lists file is stored in the file specified with CRLfile.
       The failure is expected because the python client presents the revoked certificate.
    """

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '052. CRL file with revoked certificate'
        self.params.context = 'load_revoked_cert'
        self.events.count = 1
        self.events.success = [
            "certificate verify failed",
            "certificate revoked",
            ERR_CONN_RESET
        ]
        self.events.failure = VERIFY_FAILURE_EVENTS


class VerifyCRLLeafOnlyDefault(StunnelTest):
    """Checking if CRL checking remains leaf-only by default."""

    crl_file = "ChainRevokedIntermediateCRL.pem"

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '053. CRLcheckChain omitted with revoked intermediate'
        self.events.failure = SUCCESS_FAILURE_EVENTS


class VerifyCRLCheckChain(StunnelTest):
    """Checking if CRLcheckChain accepts a valid full chain CRL bundle."""

    crl_file = "ChainCRL.pem"
    crl_check_chain = True
    crl_check_chain_default = True

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '054. CRLcheckChain with valid chain bundle'
        self.events.failure = SUCCESS_FAILURE_EVENTS


class FailureVerifyCRLCheckChainRevokedIntermediate(StunnelTest):
    """Checking if CRLcheckChain rejects a revoked intermediate certificate."""

    crl_file = "ChainRevokedIntermediateCRL.pem"
    crl_check_chain = True

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '055. CRLcheckChain with revoked intermediate'
        self.events.count = 2
        self.events.success = [
            "CERT: Pre-verification error: certificate revoked",
            r"Rejected by CERT at depth=1"
        ]
        self.events.failure = VERIFY_FAILURE_EVENTS


class FailureVerifyCRLCheckChainMissingIssuer(StunnelTest):
    """Checking if CRLcheckChain fails closed without the issuer CRL."""

    crl_check_chain = True

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '056. CRLcheckChain missing intermediate issuer CRL'
        self.events.count = 2
        self.events.success = [
            "CERT: Pre-verification error: unable to get certificate CRL",
            r"Rejected by CERT at depth=1"
        ]
        self.events.failure = VERIFY_FAILURE_EVENTS


class FailureCRLCheckChainVerifyPeer(ExpectedCRLConfigurationFailure):
    """Checking if CRLcheckChain requires verifyChain rather than verifyPeer."""

    crl_file = "ChainCRL.pem"
    crl_check_chain = True
    verify_chain = False
    verify_peer = True

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '057. CRLcheckChain with only verifyPeer'
        self.events.count = 1
        self.events.success = [
            r'"verifyChain" has to be enabled for "CRLcheckChain"'
        ]
        self.events.failure = CONFIG_FAILURE_EVENTS


class FailureCRLCheckChainNoCRL(ExpectedCRLConfigurationFailure):
    """Checking if CRLcheckChain requires a CRL source."""

    crl_file = None
    crl_check_chain = True

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '058. CRLcheckChain without CRL source'
        self.events.count = 1
        self.events.success = [
            r'Either "CRLfile" or "CRLpath" has to be configured for "CRLcheckChain"'
        ]
        self.events.failure = CONFIG_FAILURE_EVENTS


class StunnelServerTest(Plugin):
    """Stunnel server tests:
       HTTPS client --> stunnel server --> HTTP server
    """
    # pylint: disable=too-few-public-methods

    def __init__(self):
        super().__init__()
        self.description = 'Verify CRL file'


    async def perform_operation(self, cfg: Config, logger: logging.Logger) -> None:
        """Run tests"""
        stunnel = VerifyCRL(cfg, logger)
        await stunnel.test_stunnel(cfg)

        stunnel = FailureVerifyCRL(cfg, logger)
        await stunnel.test_stunnel(cfg)

        stunnel = VerifyCRLLeafOnlyDefault(cfg, logger)
        await stunnel.test_stunnel(cfg)

        stunnel = VerifyCRLCheckChain(cfg, logger)
        await stunnel.test_stunnel(cfg)

        stunnel = FailureVerifyCRLCheckChainRevokedIntermediate(cfg, logger)
        await stunnel.test_stunnel(cfg)

        stunnel = FailureVerifyCRLCheckChainMissingIssuer(cfg, logger)
        await stunnel.test_stunnel(cfg)

        stunnel = FailureCRLCheckChainVerifyPeer(cfg, logger)
        await stunnel.test_stunnel(cfg)

        stunnel = FailureCRLCheckChainNoCRL(cfg, logger)
        await stunnel.test_stunnel(cfg)
