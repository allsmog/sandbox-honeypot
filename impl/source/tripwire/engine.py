"""Operation dispatch and the failure contract."""

from .common import Invalid, is_duplicate
from .evaluate import evaluate
from .plan import plan

ENV_NAMES = ("SANDBOX_HONEYPOT_SEED", "SANDBOX_HONEYPOT_SENSOR_KEYS")


def error(pointer):
    return {"error": {"code": "invalid-request", "field": pointer}}


def run(request, environ):
    """Evaluate one request. environ is a mapping holding at most the two
    ambient variables; only those are read."""
    env = {name: environ[name] for name in ENV_NAMES if name in environ}
    try:
        if not isinstance(request, dict) or is_duplicate(request):
            raise Invalid("")
        operation = request.get("operation")
        if operation == "plan":
            return plan(request, env)
        if operation == "evaluate":
            return evaluate(request, env)
        raise Invalid("/operation")
    except Invalid as exc:
        return error(exc.pointer)
    except RecursionError:
        return error("")
