"""Integration checks using a local UDP resolver; no Internet required."""
import socket
import struct
import subprocess
import threading
import time


def query(ident, name='example.com', qtype=1):
    wire = b''.join(bytes([len(label)]) + label.encode() for label in name.split('.')) + b'\0'
    return struct.pack('!6H', ident, 0x100, 1, 0, 0, 0) + wire + struct.pack('!2H', qtype, 1)


upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
upstream.bind(('127.0.0.1', 0))
upstream.settimeout(0.1)
probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
probe.bind(('127.0.0.1', 0))
port = probe.getsockname()[1]
probe.close()
stopping = threading.Event()
errors = []


def resolver():
    while not stopping.is_set():
        try:
            data, addr = upstream.recvfrom(4096)
        except socket.timeout:
            continue
        if b'timeout' in data:
            continue
        flags = 0x8183 if b'missing' in data else 0x8180
        answer = struct.pack('!H', flags) + data[4:]
        if b'mismatch' in data:
            wrong = bytearray(data[:2] + answer)
            wrong[-3] = 28  # wrong QTYPE must not consume the pending query
            upstream.sendto(wrong, addr)
        upstream.sendto(data[:2] + answer, addr)


thread = threading.Thread(target=resolver)
thread.start()
process = subprocess.Popen(['./main', str(port), '127.0.0.1', str(upstream.getsockname()[1])],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.settimeout(3)
try:
    for _ in range(50):
        if process.poll() is not None:
            raise AssertionError('server exited during startup')
        try:
            client.sendto(query(1), ('127.0.0.1', port))
            client.settimeout(0.05)
            client.recv(4096)
            break
        except socket.timeout:
            time.sleep(0.02)
    else:
        raise AssertionError('server did not start')
    client.settimeout(3)

    def exchange(data):
        client.sendto(data, ('127.0.0.1', port))
        return client.recv(4096)

    for ident, name, qtype, rcode in [(65535, 'example.com', 1, 0),
                                      (42, 'example.com', 28, 0),
                                      (43, 'missing.example', 1, 3),
                                      (44, 'mismatch.example', 1, 0)]:
        data = query(ident, name, qtype)
        response = exchange(data)
        assert response[:2] == data[:2], 'client ID was not restored'
        assert response[12:] == data[12:], 'question changed'
        assert response[3] & 15 == rcode, 'upstream RCODE changed'

    malformed = struct.pack('!6H', 45, 0x100, 1, 0, 0, 0) + b'\x3fshort'
    assert exchange(malformed)[3] & 15 == 1, 'expected FORMERR'
    unsupported = bytearray(query(46))
    unsupported[2] = 0x11  # STATUS opcode
    assert exchange(unsupported)[3] & 15 == 4, 'expected NOTIMP'
    client.sendto(b'\0', ('127.0.0.1', port))
    assert exchange(query(47))[:2] == struct.pack('!H', 47), 'short packet crashed server'
    for ident in range(48, 51):
        response = exchange(query(ident, 'timeout.example'))
        assert response[3] & 15 == 2, 'expected SERVFAIL after timeout'
        assert response[:2] == struct.pack('!H', ident)
    assert exchange(query(51))[:2] == struct.pack('!H', 51), 'server failed after timeout cleanup'
    print('PASS: forwarding, A/AAAA, IDs, NXDOMAIN, question validation, malformed input, timeout recovery')
finally:
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        errors.append('server did not stop on SIGTERM')
    client.close()
    stopping.set()
    thread.join(timeout=2)
    upstream.close()
assert process.returncode == 0, f'server exit status {process.returncode}'
assert not errors, errors
