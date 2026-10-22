from airlock import Action, Airlock


def test_clean_request_is_allowed():
    body = {"model": "claude-sonnet-5-5", "max_tokens": 64,
            "messages": [{"role": "user", "content": "hello"}]}
    decision = Airlock().inspect(body)
    assert decision.action is Action.ALLOW
