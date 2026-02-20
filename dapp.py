from os import environ
import json
import logging
import traceback
import numpy as np
import requests

logging.basicConfig(level="INFO")
logger = logging.getLogger(__name__)

rollup_server = environ["ROLLUP_HTTP_SERVER_URL"]
logger.info(f"HTTP rollup_server url is {rollup_server}")


def hex2str(hex_str: str) -> str:
    """Decode a 0x-prefixed hex string to a UTF-8 string."""
    return bytes.fromhex(hex_str[2:]).decode("utf-8")


def str2hex(s: str) -> str:
    """Encode a UTF-8 string as a 0x-prefixed hex string."""
    return "0x" + s.encode("utf-8").hex()


def emit_notice(payload: str) -> None:
    """Send a notice to the rollup server with a hex-encoded payload."""
    notice = {"payload": str2hex(payload)}
    response = requests.post(rollup_server + "/notice", json=notice)
    logger.info(f"Notice emitted, status: {response.status_code}, body: {response.text}")


def emit_report(payload: str) -> None:
    """Send an error report to the rollup server."""
    report = {"payload": str2hex(payload)}
    requests.post(rollup_server + "/report", json=report)


def handle_advance(data):
    logger.info(f"Received advance request data {data}")
    try:
        payload_str = hex2str(data["payload"])
        logger.info(f"Decoded payload: {payload_str}")

        input_data = json.loads(payload_str)
        matrix_a = np.array(input_data["matrix_a"], dtype=float)
        matrix_b = np.array(input_data["matrix_b"], dtype=float)

        logger.info(f"Matrix A shape: {matrix_a.shape}, Matrix B shape: {matrix_b.shape}")

        result = np.matmul(matrix_a, matrix_b)
        logger.info(f"Matrix multiplication result:\n{result}")

        output = json.dumps({"result": result.tolist()})
        emit_notice(output)
        return "accept"

    except (KeyError, ValueError, json.JSONDecodeError) as e:
        error_msg = f"Invalid input. Expected JSON with 'matrix_a' and 'matrix_b' keys. Error: {e}"
        logger.error(error_msg)
        emit_report(error_msg)
        return "reject"

    except Exception as e:
        error_msg = f"Unexpected error during matrix multiplication: {traceback.format_exc()}"
        logger.error(error_msg)
        emit_report(error_msg)
        return "reject"


def handle_inspect(data):
    logger.info(f"Received inspect request data {data}")
    try:
        payload_str = hex2str(data["payload"])
        logger.info(f"Decoded inspect payload: {payload_str}")

        input_data = json.loads(payload_str)
        matrix_a = np.array(input_data["matrix_a"], dtype=float)
        matrix_b = np.array(input_data["matrix_b"], dtype=float)

        result = np.matmul(matrix_a, matrix_b)
        output = json.dumps({"result": result.tolist()})
        emit_report(output)
        return "accept"

    except Exception as e:
        error_msg = f"Error during inspect: {traceback.format_exc()}"
        logger.error(error_msg)
        emit_report(error_msg)
        return "reject"


handlers = {
    "advance_state": handle_advance,
    "inspect_state": handle_inspect,
}

finish = {"status": "accept"}

while True:
    logger.info("Sending finish")
    response = requests.post(rollup_server + "/finish", json=finish)
    logger.info(f"Received finish status {response.status_code}")
    if response.status_code == 202:
        logger.info("No pending rollup request, trying again")
    else:
        rollup_request = response.json()
        data = rollup_request["data"]
        handler = handlers[rollup_request["request_type"]]
        finish["status"] = handler(rollup_request["data"])
