from .configs import Target

__all__ = ["create_template_struct", "create_error_template"]


def create_template_struct(target: Target) -> dict:
    """
    такая структура у результатов в модуле zgrab2 http - поэтому ее так и повторил
    :return:
    """

    result = {
        "data": {
            "http": {
                "status": "http",
                "result": {"response": {"request": {}}},
            }
        }
    }
    _tls_log = {
        "tls_log": {
            "handshake_log": {
                "server_certificates": {"certificate": {"parsed": {}, "raw": ""}}
            }
        }
    }
    if target.ssl_check:
        result["data"]["http"]["result"]["response"]["request"].update(_tls_log)
    result["data"]["http"]["result"]["response"]["request"]["url"] = {}
    result["data"]["http"]["result"]["response"]["request"]["url"][
        "scheme"
    ] = target.scheme
    if len(target.hostname) > 0:
        result["data"]["http"]["result"]["response"]["request"]["url"][
            "host"
        ] = target.hostname
        result["host"] = target.hostname
        result["data"]["http"]["result"]["response"]["request"][
            "host"
        ] = target.hostname
    elif len(target.ip) > 0:
        result["data"]["http"]["result"]["response"]["request"]["url"][
            "host"
        ] = target.ip
        result["data"]["http"]["result"]["response"]["request"]["host"] = target.ip
    result["data"]["http"]["result"]["response"]["request"]["url"][
        "path"
    ] = target.endpoint
    result["data"]["http"]["result"]["response"]["request"]["method"] = target.method
    return result


def create_error_template(
    target: Target, error_str: str, status_string: str = "unknown-error"
) -> dict:
    value = {}
    value["ip"] = target.ip if target.ip else ""
    if target.hostname:
        value["hostname"] = target.hostname
    if target.port:
        value["port"] = target.port
    value["data"] = {}
    value["data"]["http"] = {}
    value["data"]["http"]["status"] = status_string
    value["data"]["http"]["error"] = error_str
    return value
