import paramiko
import logging

logger = logging.getLogger(__name__)


def create_ssh_client(hostname, username, key_path=None, password=None, port=22, timeout=10):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connect_kwargs = {
        "hostname": hostname,
        "port": port,
        "username": username,
        "timeout": timeout
    }

    if key_path:
        connect_kwargs["key_filename"] = key_path
    elif password:
        connect_kwargs["password"] = password
    else:
        connect_kwargs["look_for_keys"] = True

    logger.info("Connecting to %s@%s:%d", username, hostname, port)
    client.connect(**connect_kwargs)
    return client


def run_command(client, command, timeout=30):
    """runs a command over ssh, returns (stdout, stderr, exit_code)"""
    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace").strip()
        err = stderr.read().decode("utf-8", errors="replace").strip()
        return out, err, exit_code
    except Exception as e:
        logger.error("Failed to run '%s': %s", command, e)
        return "", str(e), -1


def close_ssh_client(client):
    if client:
        try:
            client.close()
        except Exception:
            pass
