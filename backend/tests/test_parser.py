"""Parser and normaliser unit tests."""

from datetime import datetime, timezone

from app.logs.collector import split_recognized_lines
from app.logs.normalizer import normalize
from app.logs.parser import parse_log_line


def test_ssh_failed_password() -> None:
    parsed = parse_log_line("Failed password for admin from 192.168.1.20 port 52134 ssh2")
    assert parsed.event_type == "SSH_LOGIN_FAILURE"
    assert parsed.source_ip == "192.168.1.20"
    assert parsed.username == "admin"
    assert parsed.status == "FAILED"
    assert parsed.source == "SSH"


def test_ssh_failed_invalid_user() -> None:
    parsed = parse_log_line("Failed password for invalid user root from 10.0.0.5 port 50000 ssh2")
    assert parsed.event_type == "SSH_LOGIN_FAILURE"
    assert parsed.username == "root"
    assert parsed.source_ip == "10.0.0.5"


def test_ssh_accept_password() -> None:
    parsed = parse_log_line("Accepted password for alice from 192.0.2.10 port 51234 ssh2")
    assert parsed.event_type == "SSH_LOGIN_SUCCESS"
    assert parsed.status == "SUCCESS"
    assert parsed.username == "alice"
    assert parsed.source_ip == "192.0.2.10"
    assert parsed.metadata.get("method") == "password"


def test_ssh_accept_pubkey() -> None:
    parsed = parse_log_line("Accepted publickey for deploy from 198.51.100.22 port 58711 ssh2")
    assert parsed.event_type == "SSH_LOGIN_SUCCESS"
    assert parsed.metadata.get("method") == "publickey"


def test_auth_failure_rhos_style() -> None:
    parsed = parse_log_line(
        "authentication failure; logname= uid=0 euid=0 tty=sshd ruser= rhost=198.51.100.77 user=root"
    )
    assert parsed.event_type == "AUTH_FAILURE"
    assert parsed.username == "root"
    assert parsed.source_ip == "198.51.100.77"


def test_max_attempts_exceeded() -> None:
    parsed = parse_log_line(
        "error: maximum authentication attempts exceeded for root from 198.51.100.77 port 40015 ssh2"
    )
    assert parsed.event_type == "SSH_LOGIN_FAILURE"
    assert parsed.source_ip == "198.51.100.77"


def test_spaces_in_sudo_command() -> None:
    parsed = parse_log_line(
        "bob : TTY=pts/1 ; PWD=/var/www ; USER=root ; COMMAND=/bin/bash -c chmod 777 /etc/shadow"
    )
    assert parsed.event_type == "SUDO_COMMAND"
    assert parsed.username == "bob"
    assert parsed.metadata["target_user"] == "root"
    assert "chmod" in parsed.metadata["command"]


def test_user_created() -> None:
    parsed = parse_log_line(
        "useradd[2201]: new user: name=tempadmin, UID=1002, GID=1002, home=/home/tempadmin, shell=/bin/bash"
    )
    assert parsed.event_type == "USER_CREATED"
    assert parsed.username == "tempadmin"


def test_http_ok_request() -> None:
    parsed = parse_log_line(
        '192.0.2.44 - - [22/Sep/2026:06:11:01 +0000] "GET /index.html HTTP/1.1" 200 5120'
    )
    assert parsed.event_type == "HTTP_REQUEST"
    assert parsed.source_ip == "192.0.2.44"
    assert parsed.status == "SUCCESS"
    assert parsed.metadata["status_code"] == 200
    assert parsed.metadata["method"] == "GET"
    assert parsed.timestamp is not None


def test_http_403() -> None:
    parsed = parse_log_line(
        '198.51.100.7 - - [22/Sep/2026:06:10:13 +0000] "GET /../../etc/passwd HTTP/1.1" 403 1536'
    )
    assert parsed.event_type == "HTTP_SUSPICIOUS_REQUEST"
    assert parsed.status == "SUSPICIOUS"
    assert "path_traversal" in parsed.metadata["suspicious_signatures"]


def test_http_sql_injection() -> None:
    parsed = parse_log_line(
        '198.51.100.7 - - [22/Sep/2026:06:10:14 +0000] "GET /admin/index.php?user=union%20select%20password%20from%20users HTTP/1.1" 404 512'
    )
    assert parsed.event_type == "HTTP_SUSPICIOUS_REQUEST"
    assert "sql_injection" in parsed.metadata["suspicious_signatures"]


def test_unknown_line_does_not_crash() -> None:
    parsed = parse_log_line("some completely random log content ########")
    assert parsed.event_type == "UNKNOWN"
    assert parsed.status == "UNKNOWN"
    assert parsed.message == "some completely random log content ########"


def test_empty_line_returns_unknown() -> None:
    parsed = parse_log_line("")
    assert parsed.event_type == "UNKNOWN"


def test_normalizer_cleans_and_caps_fields() -> None:
    parsed = parse_log_line("Failed password for admin from 192.168.1.20 port 52134 ssh2")
    data = normalize(parsed)
    assert data["source_ip"] == "192.168.1.20"
    assert data["username"] == "admin"
    assert data["event_type"] == "SSH_LOGIN_FAILURE"
    assert data["timestamp"].tzinfo is not None
    assert isinstance(data["metadata"], dict)


def test_normalizer_uses_fallback_timestamp() -> None:
    parsed = parse_log_line("Accepted password for alice from 192.0.2.10 port 51234 ssh2")
    fallback = datetime(2026, 1, 1, tzinfo=timezone.utc)
    data = normalize(parsed, fallback_timestamp=fallback)
    assert data["timestamp"] == fallback


def test_normalizer_rejects_empty_message() -> None:
    parsed = parse_log_line("   ")
    import pytest

    with pytest.raises(ValueError):
        normalize(parsed)


def test_syslog_prefix_timestamp_extracted() -> None:
    parsed = parse_log_line(
        "Sep 22 06:34:11 sentinelx sshd[2411]: Failed password for invalid user root from 203.0.113.10 port 52341 ssh2"
    )
    assert parsed.event_type == "SSH_LOGIN_FAILURE"
    assert parsed.status == "FAILED"
    assert parsed.source_ip == "203.0.113.10"
    assert parsed.timestamp is not None
    assert parsed.timestamp.hour == 6
    assert parsed.timestamp.minute == 34
    assert parsed.timestamp.second == 11
    assert parsed.timestamp.tzinfo is not None


def test_split_recognized_lines_partitions_entries() -> None:
    recognized, skipped = split_recognized_lines(
        [
            "Failed password for admin from 203.0.113.10 port 52347 ssh2",
            "   ",
            "hello world, this is not a log",
            "this is a random file",
            "alice : TTY=tty1 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls",
        ]
    )
    assert recognized == [
        "Failed password for admin from 203.0.113.10 port 52347 ssh2",
        "alice : TTY=tty1 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls",
    ]
    assert skipped == 2


def test_split_recognized_lines_all_skipped_when_nothing_matches() -> None:
    recognized, skipped = split_recognized_lines(["hello world", "123456", "garbage"])
    assert recognized == []
    assert skipped == 3