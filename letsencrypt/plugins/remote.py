"""Manual2 plugin."""
import os
import logging
import pipes
import requests
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

import zope.component
import zope.interface

from acme import challenges

from letsencrypt import errors
from letsencrypt import interfaces
from letsencrypt.plugins import common


logger = logging.getLogger(__name__)

class Authenticator(common.Plugin):
    """Remote Authenticator.

    This plugin allows generation of the certificate on a host
    that does not serve the target domain by sending http-01 
    challenges information to the domain serving host.
    The host serving the target domain must accept POST of ...
    TODO Document POST

    .. todo:: Support for `~.challenges.TLSSNI01`.

    """
    zope.interface.implements(interfaces.IAuthenticator)
    zope.interface.classProvides(interfaces.IPluginFactory)

    description = "Send challenge information to a remote host"

    # a disclaimer about your current IP being transmitted to Let's Encrypt's servers.
    IP_DISCLAIMER = """\
NOTE: The IP of this machine will be publicly logged as having requested this certificate. \

Are you OK with your IP being logged?
"""

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)

    @classmethod
    def add_parser_arguments(cls, add):
        add("url",
            help="Set the remote URL for remote authentication. Must accept POST with body TODO")
        add("public-ip-logging-ok", action="store_true",
            help="Automatically allows public IP logging.")

    def prepare(self):  # pylint: disable=missing-docstring,no-self-use
        pass  # pragma: no cover

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return ("This plugin allows generation of the certificate on a host "
                "that does not serve the target domain by sending http-01 " 
                "challenges information to the domain serving host. "
                "The host serving the target domain must accept POST of ... "
                "TODO Document POST")

    def get_chall_pref(self, domain):
        # pylint: disable=missing-docstring,no-self-use,unused-argument
        return [challenges.HTTP01]

    def perform(self, achalls):  # pylint: disable=missing-docstring
        responses = []
        for achall in achalls:
            responses.append(self._perform_single(achall))
        return responses

    @classmethod
    def _test_mode_busy_wait(cls, port):
        while True:
            time.sleep(1)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.connect(("localhost", port))
            except socket.error:  # pragma: no cover
                pass
            else:
                break
            finally:
                sock.close()

    def _perform_single(self, achall):
        
        # same path for each challenge response would be easier for
        # users, but will not work if multiple domains point at the
        # same server: default command doesn't support virtual hosts
        response, validation = achall.response_and_validation()

        port = (response.port if self.config.http01_port is None
                else int(self.config.http01_port))
        
        # encoded_token: url path
        encoded_token = achall.chall.encode("token")
        
        # validation: response body
        # TODO(kuba): pipes still necessary?
        validation=pipes.quote(validation)
        
        if not self.conf("public-ip-logging-ok"):
            if not zope.component.getUtility(interfaces.IDisplay).yesno(
                    self.IP_DISCLAIMER, "Yes", "No"):
                raise errors.PluginError("Must agree to IP logging to proceed")

        payload = {'challenge_path': encoded_token, 'challenge_body': validation}
        post_response = requests.post(self.conf("url"), json=payload)
        if post_response.status_code != 200:
            logger.error("Failed to POST challenge to server: " + str(post_response))
            return False

        if not response.simple_verify(
                achall.chall, achall.domain,
                achall.account_key.public_key(), self.config.http01_port):
            logger.warning("Self-verify of challenge failed.")
        
        return response

    # def _notify_and_wait(self, message):  # pylint: disable=no-self-use
    #     # TODO: IDisplay wraps messages, breaking the command
    #     #answer = zope.component.getUtility(interfaces.IDisplay).notification(
    #     #    message=message, height=25, pause=True)
    #     sys.stdout.write(message)
    #     raw_input("Press ENTER to continue")

    def cleanup(self, achalls):
        # pylint: disable=missing-docstring,no-self-use,unused-argument
        # if self.conf("test-mode"):
        #     assert self._httpd is not None, (
        #         "cleanup() must be called after perform()")
        #     if self._httpd.poll() is None:
        #         logger.debug("Terminating manual command process")
        #         os.killpg(self._httpd.pid, signal.SIGTERM)
        #     else:
        #         logger.debug("Manual command process already terminated "
        #                      "with %s code", self._httpd.returncode)
        #     shutil.rmtree(self._root)
        return
