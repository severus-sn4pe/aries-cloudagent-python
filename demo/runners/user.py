import asyncio
import json
import logging
import os
import sys
import time

from qrcode import QRCode

from aiohttp import ClientError

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # noqa

from runners.support.agent import DemoAgent, default_genesis_txns
from runners.support.utils import (
    log_json,
    log_msg,
    log_status,
    log_timer,
    prompt,
    prompt_loop,
    require_indy,
)

CRED_PREVIEW_TYPE = (
    "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/issue-credential/1.0/credential-preview"
)
AGENT_NAME = os.getenv("AGENT_NAME")
LOGGER = logging.getLogger(__name__)

AGENT_SEED = (AGENT_NAME + str(int(time.time()))).ljust(32, '0')[0:32]


class UserAgent(DemoAgent):
    def __init__(self, http_port: int, admin_port: int, no_auto: bool = False, **kwargs):
        super().__init__(
            "{0} Agent".format(AGENT_NAME),
            http_port,
            admin_port,
            prefix=AGENT_NAME,
            extra_args=[] if no_auto else ["--auto-accept-invites",
                                           "--auto-accept-requests",
                                           "--auto-store-credential"],
            seed=AGENT_SEED,
            **kwargs,
        )
        self.connection_id = None
        self._connection_ready = asyncio.Future()
        self.cred_state = {}
        self.cred_attrs = {}

        self.schemas = {
            "work_experience": ["position", "employer", "city", "country",
                                "periodFrom", "periodTo", "ongoing", "activities", "website"],
            # "education": ["title", "organisation", "city", "country",
            #              "periodFrom", "periodTo", "ongoing", "subject", "website", "field", "validUntil"]
        }
        self.versions = {
            "work_experience": "1.1.1",
            # "education": "1.1.1"
        }

    async def detect_connection(self):
        await self._connection_ready

    @property
    def connection_ready(self):
        return self._connection_ready.done() and self._connection_ready.result()

    async def handle_connections(self, message):
        if message["connection_id"] == self.connection_id:
            if message["state"] in ["active", "response"]:
                self.log("Connected")
                self._connection_ready.set_result(True)
                if not self._connection_ready.done():
                    self._connection_ready.set_result(True)

    async def handle_issue_credential(self, message):
        state = message["state"]
        credential_exchange_id = message["credential_exchange_id"]
        prev_state = self.cred_state.get(credential_exchange_id)
        if prev_state == state:
            return  # ignore
        self.cred_state[credential_exchange_id] = state

        self.log(f"Credential: state = {state}, credential_exchange_id = {credential_exchange_id}")

        if state == "request_received":
            log_status("#17 Issue credential to X")
            # issue credentials based on the credential_definition_id
            cred_attrs = self.cred_attrs[message["credential_definition_id"]]
            cred_preview = {
                "@type": CRED_PREVIEW_TYPE,
                "attributes": [
                    {"name": n, "value": v} for (n, v) in cred_attrs.items()
                ],
            }
            try:
                cred_ex_rec = await self.admin_POST(
                    f"/issue-credential/records/{credential_exchange_id}/issue",
                    {
                        "comment": f"Issuing credential, exchange {credential_exchange_id}",
                        "credential_preview": cred_preview,
                    },
                )
                rev_reg_id = cred_ex_rec.get("revoc_reg_id")
                cred_rev_id = cred_ex_rec.get("revocation_id")
                if rev_reg_id:
                    self.log(f"Revocation registry id: {rev_reg_id}")
                if cred_rev_id:
                    self.log(f"Credential revocation id: {cred_rev_id}")
            except ClientError:
                pass

        elif state == "offer_received":
            log_status("#15 After receiving credential offer, send credential request")
            await self.admin_POST(f"/issue-credential/records/{credential_exchange_id}/send-request")

        elif state == "credential_acked":
            cred_id = message["credential_id"]
            self.log(f"Stored credential {cred_id} in wallet")
            log_status(f"#18.1 Stored credential {cred_id} in wallet")
            resp = await self.admin_GET(f"/credential/{cred_id}")
            log_json(resp, label="Credential details:")
            log_json(
                message["credential_request_metadata"],
                label="Credential request metadata:",
            )
            self.log("credential_id", message["credential_id"])
            self.log("credential_definition_id", message["credential_definition_id"])
            self.log("schema_id", message["schema_id"])

    async def handle_present_proof(self, message):
        state = message["state"]

        presentation_exchange_id = message["presentation_exchange_id"]
        self.log(f"Presentation: state ={state} presentation_exchange_id ={presentation_exchange_id}")

        if state == "presentation_received":
            log_status("#27 Process the proof provided by X")
            log_status("#28 Check if proof is valid")
            proof = await self.admin_POST(f"/present-proof/records/{presentation_exchange_id}/verify-presentation")
            self.log("Proof =", proof["verified"])

    async def handle_basicmessages(self, message):
        self.log(f"Received message:{message['content']}")


async def main(start_port: int, no_auto: bool = False, revocation: bool = False, show_timing: bool = False):
    genesis = await default_genesis_txns()
    if not genesis:
        print("Error retrieving ledger genesis transactions")
        sys.exit(1)

    agent = None

    try:
        log_status("#1 Provision an agent and wallet, get back configuration details")
        agent = UserAgent(
            start_port,
            start_port + 1,
            genesis_data=genesis,
            no_auto=no_auto,
            timing=show_timing,
        )
        await agent.listen_webhooks(start_port + 2)
        await agent.register_did()

        with log_timer("Startup duration:"):
            await agent.start_process()
        log_msg("Admin URL is at:", agent.admin_url)
        log_msg("Endpoint URL is at:", agent.endpoint)

        await agent.register_schema_facade("work_experience", True)
        # await agent.register_schema_facade("education", True)

        connection = await agent.admin_POST("/connections/create-invitation")

        agent.connection_id = connection["connection_id"]

        qr = QRCode()
        qr.add_data(connection["invitation_url"])
        log_msg(
            "Use the following JSON to accept the invite from another demo agent."
            " Or use the QR code to connect from a mobile agent."
        )
        log_msg(
            json.dumps(connection["invitation"]), label="Invitation Data:", color=None
        )
        qr.print_ascii(invert=True)

        log_msg("Waiting for connection...")
        await agent.detect_connection()

        exchange_tracing = False
        options = (
            "    (1) Issue Credential\n"
            "    (2) Send Proof Request\n"
            "    (3) Send Message\n"
            "    (4) Revoke Credential\n"
            "    (5) Publish Revocations\n"
            "    (6) Add Revocation Registry\n"
            "    (T) Toggle tracing on credential/proof exchange\n"
            "    (X) Exit?\n[1/2/3/4/5/6/T/X] "
        )

        async for option in prompt_loop(options):
            if option is not None:
                option = option.strip()

            if option is None or option in "xX":
                break

            elif option in "tT":
                exchange_tracing = not exchange_tracing
                log_msg(
                    ">>> Credential/Proof Exchange Tracing is {}".format(
                        "ON" if exchange_tracing else "OFF"
                    )
                )
            elif option == "1":
                log_status("#13 Issue credential offer to X")
                credential_name = 'work_experience'
                credential_definition_id = agent.credential_definition_ids[credential_name]
                attributes = {
                    "position": "Pos",
                    "employer": "Test",
                    "city": "A",
                    "country": "B",
                    "periodFrom": "12345",
                    "periodTo": "20000",
                    "ongoing": "0",
                    "activities": "",
                    "website": "",
                }

                schema_id = agent.schema_ids[credential_name]
                schemaInfo = schema_id.split(':')
                credential = {
                    "schema_issuer_did": schemaInfo[0],
                    "schema_id": schema_id,
                    "schema_name": schemaInfo[2],
                    "issuer_did": schemaInfo[0],
                    "schema_version": '1.1.1',
                    "cred_def_id": credential_definition_id,
                    "connection_id": agent.connection_id,
                    "credential_proposal": {
                        "@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/issue-credential/1.0/credential-preview",
                        "attributes": [{"name": n, "value": v} for (n, v) in attributes.items()],
                    },
                    # "auto_remove": False,
                    # "trace": exchange_tracing,
                }

                await agent.admin_POST("/issue-credential/send", credential)

            elif option == "2":
                log_status("#20 Request proof of degree from alice")
                req_attrs = [
                    {"name": "name", "restrictions": [{"issuer_did": agent.did}]},
                    {"name": "date", "restrictions": [{"issuer_did": agent.did}]},
                ]
                if revocation:
                    req_attrs.append(
                        {
                            "name": "degree",
                            "restrictions": [{"issuer_did": agent.did}],
                            "non_revoked": {"to": int(time.time() - 1)},
                        },
                    )
                else:
                    req_attrs.append(
                        {"name": "degree", "restrictions": [{"issuer_did": agent.did}]}
                    )
                req_preds = [
                    # test zero-knowledge proofs
                    {
                        "name": "age",
                        "p_type": ">=",
                        "p_value": 18,
                        "restrictions": [{"issuer_did": agent.did}],
                    }
                ]
                indy_proof_request = {
                    "name": "Proof of Education",
                    "version": "1.0",
                    "requested_attributes": {
                        f"0_{req_attr['name']}_uuid": req_attr for req_attr in req_attrs
                    },
                    "requested_predicates": {
                        f"0_{req_pred['name']}_GE_uuid": req_pred
                        for req_pred in req_preds
                    },
                }
                if revocation:
                    indy_proof_request["non_revoked"] = {"to": int(time.time())}
                proof_request_web_request = {
                    "connection_id": agent.connection_id,
                    "proof_request": indy_proof_request,
                    "trace": exchange_tracing,
                }
                await agent.admin_POST("/present-proof/send-request", proof_request_web_request)

            elif option == "3":
                msg = await prompt("Enter message: ")
                await agent.admin_POST(
                    f"/connections/{agent.connection_id}/send-message", {"content": msg}
                )
            elif option == "4" and revocation:
                rev_reg_id = (await prompt("Enter revocation registry ID: ")).strip()
                cred_rev_id = (await prompt("Enter credential revocation ID: ")).strip()
                publish = json.dumps(
                    (await prompt("Publish now? [Y/N]: ", default="N")).strip()
                    in ("yY")
                )
                try:
                    await agent.admin_POST(
                        "/issue-credential/revoke"
                        f"?publish={publish}"
                        f"&rev_reg_id={rev_reg_id}"
                        f"&cred_rev_id={cred_rev_id}"
                    )
                except ClientError:
                    pass
            elif option == "5" and revocation:
                try:
                    resp = await agent.admin_POST("/issue-credential/publish-revocations", {})
                    agent.log(
                        "Published revocations for {} revocation registr{} {}".format(
                            len(resp["rrid2crid"]),
                            "y" if len(resp) == 1 else "ies",
                            json.dumps([k for k in resp["rrid2crid"]], indent=4),
                        )
                    )
                except ClientError:
                    pass
            elif option == "6" and revocation:
                log_status("#19 Add another revocation registry")
                await agent.create_and_publish_revocation_registry(credential_definition_id, 20)

        if show_timing:
            timing = await agent.fetch_timing()
            if timing:
                for line in agent.format_timing(timing):
                    log_msg(line)

    finally:
        terminated = True
        try:
            if agent:
                await agent.terminate()
        except Exception:
            LOGGER.exception("Error terminating agent:")
            terminated = False

    await asyncio.sleep(0.1)

    if not terminated:
        os._exit(1)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Runs a User agent.")
    parser.add_argument("--no-auto", action="store_true", help="Disable auto issuance")
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=8020,
        metavar=("<port>"),
        help="Choose the starting port number to listen on",
    )
    parser.add_argument("--revocation", action="store_true", help="Enable credential revocation")
    parser.add_argument("--timing", action="store_true", help="Enable timing information")
    args = parser.parse_args()

    ENABLE_PYDEVD_PYCHARM = os.getenv("ENABLE_PYDEVD_PYCHARM", "").lower()
    ENABLE_PYDEVD_PYCHARM = ENABLE_PYDEVD_PYCHARM and ENABLE_PYDEVD_PYCHARM not in (
        "false",
        "0",
    )
    PYDEVD_PYCHARM_HOST = os.getenv("PYDEVD_PYCHARM_HOST", "localhost")
    PYDEVD_PYCHARM_CONTROLLER_PORT = int(
        os.getenv("PYDEVD_PYCHARM_CONTROLLER_PORT", 5001)
    )

    if ENABLE_PYDEVD_PYCHARM:
        try:
            import pydevd_pycharm

            print(
                f"User remote debugging to {PYDEVD_PYCHARM_HOST}:{PYDEVD_PYCHARM_CONTROLLER_PORT}"
            )
            pydevd_pycharm.settrace(
                host=PYDEVD_PYCHARM_HOST,
                port=PYDEVD_PYCHARM_CONTROLLER_PORT,
                stdoutToServer=True,
                stderrToServer=True,
                suspend=False,
            )
        except ImportError:
            print("pydevd_pycharm library was not found")

    require_indy()

    try:
        asyncio.get_event_loop().run_until_complete(
            main(args.port, args.no_auto, args.revocation, args.timing)
        )
    except KeyboardInterrupt:
        os._exit(1)
