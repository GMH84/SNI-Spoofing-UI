import os
import sys
import ctypes
import threading
import collections
import urllib.request
import urllib.error
import webbrowser
import webview
import socket
import struct
import asyncio
import time
from abc import ABC, abstractmethod
from flask import Flask, request, jsonify, send_from_directory

# Third-party library dependency
try:
    from pydivert import WinDivert, Packet
except ImportError:
    print("Error: The 'pydivert' library is required to run this script.")
    print("Please install it using: pip install pydivert")
    sys.exit(1)

# --- Path Handling for PyInstaller ---
if getattr(sys, 'frozen', False):
    BUNDLE_DIR = sys._MEIPASS
    CURRENT_DIR = os.path.dirname(sys.executable)
else:
    BUNDLE_DIR = os.path.dirname(os.path.abspath(__file__))
    CURRENT_DIR = BUNDLE_DIR

app = Flask(__name__, static_folder=BUNDLE_DIR)

CONFIG_FILE = os.path.join(CURRENT_DIR, 'config.ini')

# Current Application Build version
CURRENT_VERSION = "1.0.0"

# Thread-safe circular buffer for live logs
log_buffer = collections.deque(maxlen=100)
log_lock = threading.Lock()
log_buffer.append("[System] Ready to connect. Click Power button to start.")

# --- Real-Time Performance Statistics ---
total_bytes = 0
speed_bytes_last_sec = 0
speed_kb_s = 0.0
last_ping_ms = 0
start_time = None

# Default Configuration values
DEFAULT_CONFIG = {
    "listen": "127.0.0.1:40443",
    "connect": "104.19.229.21:443",
    "fake-sni": "hcaptcha.com"
}

# --- TCP Bypass Engine Globals ---
is_engine_running = False
async_loop = None
async_thread = None
proxy_task = None
mother_sock = None
fake_tcp_injector = None
injector_thread = None

# Network global params loaded from config
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 40443
CONNECT_IP = "104.19.229.21"
CONNECT_PORT = 443
FAKE_SNI = b"hcaptcha.com"
INTERFACE_IPV4 = ""
DATA_MODE = "tls"
BYPASS_METHOD = "wrong_seq"

fake_injective_connections = {}


# =====================================================================
# SYSTEM UTILITIES & FILE HANDLERS
# =====================================================================

def get_exe_dir():
    return CURRENT_DIR


def read_config():
    if not os.path.exists(CONFIG_FILE):
        write_config(DEFAULT_CONFIG)
        append_system_log("[System] config.ini not found. Created with default values.")
        return DEFAULT_CONFIG
    
    config = {}
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if '=' in line and not line.startswith('#'):
                    key, val = line.split('=', 1)
                    config[key.strip()] = val.strip()
    except Exception as e:
        append_system_log(f"[System Error] Failed to read config: {e}")
    
    for k, v in DEFAULT_CONFIG.items():
        if k not in config:
            config[k] = v
    return config


def write_config(config):
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        for key, val in config.items():
            f.write(f"{key} = {val}\n")


def append_system_log(msg: str):
    with log_lock:
        log_buffer.append(msg)


def format_volume(bytes_count):
    if bytes_count < 1024:
        return f"{bytes_count} B"
    elif bytes_count < 1024 * 1024:
        return f"{bytes_count / 1024:.1f} KB"
    elif bytes_count < 1024 * 1024 * 1024:
        return f"{bytes_count / (1024 * 1024):.1f} MB"
    else:
        return f"{bytes_count / (1024 * 1024 * 1024):.1f} GB"


def format_speed(kb_s):
    if kb_s < 1024:
        return f"{kb_s:.1f} KB/s"
    else:
        return f"{kb_s / 1024:.1f} MB/s"


# =====================================================================
# PERFORMANCE SPEED MONITORS
# =====================================================================

def speed_calculator_worker():
    global speed_bytes_last_sec, speed_kb_s
    while True:
        time.sleep(1.0)
        speed_kb_s = speed_bytes_last_sec / 1024.0
        speed_bytes_last_sec = 0

threading.Thread(target=speed_calculator_worker, daemon=True).start()


# =====================================================================
# NETWORK TOOLS
# =====================================================================

def get_default_interface_ipv4(addr="8.8.8.8") -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((addr, 53))
    except OSError:
        return ""
    else:
        return s.getsockname()[0]
    finally:
        s.close()


# =====================================================================
# PACKET TEMPLATES
# =====================================================================

class ClientHelloMaker:
    tls_ch_template_str = (
        "1603010200010001fc030341d5b549d9cd1adfa7296c8418d157dc7b624c842824ff49"
        "3b9375bb48d34f2b20bf018bcc90a7c89a230094815ad0c15b736e38c01209d72d282cb"
        "5e2105328150024130213031301c02cc030c02bc02fcca9cca8c024c028c023c027009f"
        "009e006b006700ff0100018f0000000b00090000066d63692e6972000b000403000102"
        "000a00160014001d0017001e0019001801000101010201030104002300000010000e00"
        "0c02683208687474702f312e310016000000170000000d002a00280403050306030807"
        "08080809080a080b080408050806040105010601030303010302040205020602002b00"
        "050403040303002d00020101003300260024001d0020435bacc4d05f9d41fef44ab3ad"
        "55616c36e0613473e2338770efdaa98693d217001500d5000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000"
    )
    tls_ch_template = bytes.fromhex(tls_ch_template_str)
    template_sni = "mci.ir".encode()
    static1 = tls_ch_template[:11]
    static2 = b"\x20"
    static3 = tls_ch_template[76:120]
    static4 = tls_ch_template[127 + len(template_sni):262 + len(template_sni)]
    static5 = b"\x00\x15"

    @classmethod
    def get_client_hello_with(cls, rnd: bytes, sess_id: bytes, target_sni: bytes,
                              key_share: bytes) -> bytes:
        server_name_ext = struct.pack("!H", len(target_sni) + 5) + struct.pack("!H",
                                                                               len(target_sni) + 3) + b"\x00" + struct.pack(
            "!H", len(target_sni)) + target_sni
        padding_ext = struct.pack("!H", 219 - len(target_sni)) + (b"\x00" * (219 - len(target_sni)))
        return cls.static1 + rnd + cls.static2 + sess_id + cls.static3 + server_name_ext + cls.static4 + key_share + cls.static5 + padding_ext


# =====================================================================
# MONITOR CONNECTION
# =====================================================================

class MonitorConnection:
    def __init__(self, sock: socket.socket, src_ip, dst_ip, src_port, dst_port):
        self.monitor = True
        self.syn_seq = -1
        self.syn_ack_seq = -1
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.id = (self.src_ip, self.src_port, self.dst_ip, self.dst_port)
        self.thread_lock = threading.Lock()
        self.sock = sock
        self.syn_sent_time = -1


# =====================================================================
# INJECTOR
# =====================================================================

class TcpInjector(ABC):
    def __init__(self, w_filter: str):
        self.w_filter = w_filter
        self.w: WinDivert = WinDivert(w_filter)
        self.running = True

    @abstractmethod
    def inject(self, packet: Packet):
        sys.exit("Not implemented")

    def run(self):
        try:
            with self.w:
                while self.running:
                    packet = self.w.recv(65575)
                    if packet is None:
                        break
                    self.inject(packet)
        except Exception as e:
            append_system_log(f"[System Debug] WinDivert capture stopped: {e}")

    def stop(self):
        self.running = False
        try:
            self.w.close()
        except Exception:
            pass


# =====================================================================
# FAKE TCP INTERCEPTOR
# =====================================================================

class FakeInjectiveConnection(MonitorConnection):
    def __init__(self, sock: socket.socket, src_ip, dst_ip,
                 src_port, dst_port, fake_data: bytes, bypass_method: str, peer_sock: socket.socket):
        super().__init__(sock, src_ip, dst_ip, src_port, dst_port)
        self.fake_data = fake_data
        self.sch_fake_sent = False
        self.fake_sent = False
        self.t2a_event = asyncio.Event()
        self.t2a_msg = ""
        self.bypass_method = bypass_method
        self.peer_sock = peer_sock
        self.running_loop = asyncio.get_running_loop()


class FakeTcpInjector(TcpInjector):
    def __init__(self, w_filter: str, connections: dict[tuple, FakeInjectiveConnection]):
        super().__init__(w_filter)
        self.connections = connections

    def fake_send_thread(self, packet: Packet, connection: FakeInjectiveConnection):
        time.sleep(0.001)
        with connection.thread_lock:
            if not connection.monitor:
                return

            packet.tcp.psh = True
            packet.ip.packet_len = packet.ip.packet_len + len(connection.fake_data)
            packet.tcp.payload = connection.fake_data
            if packet.ipv4:
                packet.ipv4.ident = (packet.ipv4.ident + 1) & 0xffff
            
            if connection.bypass_method == "wrong_seq":
                packet.tcp.seq_num = (connection.syn_seq + 1 - len(packet.tcp.payload)) & 0xffffffff
                connection.fake_sent = True
                append_system_log(f"[{connection.id}] Sending fake payload (wrong_seq)...")
                self.w.send(packet, True)
            else:
                sys.exit("not implemented method!")

    def on_unexpected_packet(self, packet: Packet, connection: FakeInjectiveConnection, info_m: str):
        append_system_log(f"[{connection.id}] Unexpected packet: {info_m}")
        try:
            connection.sock.close()
        except Exception:
            pass
        try:
            connection.peer_sock.close()
        except Exception:
            pass
        connection.monitor = False
        connection.t2a_msg = "unexpected_close"
        connection.running_loop.call_soon_threadsafe(connection.t2a_event.set)
        try:
            self.w.send(packet, False)
        except Exception:
            pass

    def on_inbound_packet(self, packet: Packet, connection: FakeInjectiveConnection):
        if connection.syn_seq == -1:
            self.on_unexpected_packet(packet, connection, "unexpected inbound packet, no syn sent!")
            return
        if packet.tcp.ack and packet.tcp.syn and (not packet.tcp.rst) and (not packet.tcp.fin) and (
                len(packet.tcp.payload) == 0):
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            if connection.syn_ack_seq != -1 and connection.syn_ack_seq != seq_num:
                self.on_unexpected_packet(packet, connection,
                                          "unexpected inbound syn-ack packet, seq change! " + str(seq_num) + " " + str(
                                              connection.syn_ack_seq))
                return
            if ack_num != ((connection.syn_seq + 1) & 0xffffffff):
                self.on_unexpected_packet(packet, connection,
                                          "unexpected inbound syn-ack packet, ack not matched! " + str(
                                              ack_num) + " " + str(connection.syn_seq))
                return
            connection.syn_ack_seq = seq_num
            
            # Record Ping RTT
            if connection.syn_sent_time != -1:
                rtt = (time.time() - connection.syn_sent_time) * 1000.0
                global last_ping_ms
                last_ping_ms = int(rtt)
                
            self.w.send(packet, False)
            return
        if packet.tcp.ack and (not packet.tcp.syn) and (not packet.tcp.rst) and (
                not packet.tcp.fin) and (len(packet.tcp.payload) == 0) and connection.fake_sent:
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            if connection.syn_ack_seq == -1 or ((connection.syn_ack_seq + 1) & 0xffffffff) != seq_num:
                self.on_unexpected_packet(packet, connection,
                                          "unexpected inbound ack packet, seq not matched! " + str(seq_num) + " " + str(
                                              connection.syn_ack_seq))
                return
            if ack_num != ((connection.syn_seq + 1) & 0xffffffff):
                self.on_unexpected_packet(packet, connection,
                                          "unexpected inbound ack packet, ack not matched! " + str(ack_num) + " " + str(
                                              connection.syn_seq))
                return

            connection.monitor = False
            connection.t2a_msg = "fake_data_ack_recv"
            append_system_log(f"[{connection.id}] Inbound ACK for fake payload validated.")
            connection.running_loop.call_soon_threadsafe(connection.t2a_event.set)
            return
        self.on_unexpected_packet(packet, connection, "unexpected inbound packet")
        return

    def on_outbound_packet(self, packet: Packet, connection: FakeInjectiveConnection):
        if connection.sch_fake_sent:
            self.on_unexpected_packet(packet, connection, "unexpected outbound packet, recv packet after fake sent!")
            return
        if packet.tcp.syn and (not packet.tcp.ack) and (not packet.tcp.rst) and (not packet.tcp.fin) and (
                len(packet.tcp.payload) == 0):
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            if ack_num != 0:
                self.on_unexpected_packet(packet, connection, "unexpected outbound syn packet, ack_num is not zero!")
                return
            if connection.syn_seq != -1 and connection.syn_seq != seq_num:
                self.on_unexpected_packet(packet, connection, "unexpected outbound syn packet, seq not matched! " + str(
                    seq_num) + " " + str(connection.syn_seq))
                return
            connection.syn_seq = seq_num
            connection.syn_sent_time = time.time()
            self.w.send(packet, False)
            return
        if packet.tcp.ack and (not packet.tcp.syn) and (not packet.tcp.rst) and (not packet.tcp.fin) and (
                len(packet.tcp.payload) == 0):
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            if connection.syn_seq == -1 or ((connection.syn_seq + 1) & 0xffffffff) != seq_num:
                self.on_unexpected_packet(packet, connection,
                                          "unexpected outbound ack packet, seq not matched! " + str(
                                              seq_num) + " " + str(
                                              connection.syn_seq))
                return
            if connection.syn_ack_seq == -1 or ack_num != ((connection.syn_ack_seq + 1) & 0xffffffff):
                self.on_unexpected_packet(packet, connection,
                                          "unexpected outbound ack packet, ack not matched! " + str(
                                              ack_num) + " " + str(
                                              connection.syn_ack_seq))
                return

            self.w.send(packet, False)
            connection.sch_fake_sent = True
            threading.Thread(target=self.fake_send_thread, args=(packet, connection), daemon=True).start()
            return
        self.on_unexpected_packet(packet, connection, "unexpected outbound packet")
        return

    def inject(self, packet: Packet):
        if packet.is_inbound:
            c_id = (packet.ip.dst_addr, packet.tcp.dst_port, packet.ip.src_addr, packet.tcp.src_port)
            try:
                connection = self.connections[c_id]
            except KeyError:
                self.w.send(packet, False)
            else:
                with connection.thread_lock:
                    if not connection.monitor:
                        self.w.send(packet, False)
                        return
                    self.on_inbound_packet(packet, connection)
        elif packet.is_outbound:
            c_id = (packet.ip.src_addr, packet.tcp.src_port, packet.ip.dst_addr, packet.tcp.dst_port)
            try:
                connection = self.connections[c_id]
            except KeyError:
                self.w.send(packet, False)
            else:
                with connection.thread_lock:
                    if not connection.monitor:
                        self.w.send(packet, False)
                        return
                    self.on_outbound_packet(packet, connection)
        else:
            sys.exit("impossible direction!")


# =====================================================================
# CORE ENGINE LIFE CYCLE LIFELINE
# =====================================================================

async def relay_main_loop_simple(sock_src: socket.socket, sock_dst: socket.socket, first_prefix_data: bytes):
    global total_bytes, speed_bytes_last_sec
    loop = asyncio.get_running_loop()
    try:
        while True:
            data = await loop.sock_recv(sock_src, 65575)
            if not data:
                break
            if first_prefix_data:
                data = first_prefix_data + data
                first_prefix_data = b""
            await loop.sock_sendall(sock_dst, data)
            
            # Record performance statistics
            data_len = len(data)
            total_bytes += data_len
            speed_bytes_last_sec += data_len
    except asyncio.CancelledError:
        raise
    except Exception as e:
        pass


async def handle_connection_task(incoming_sock: socket.socket, incoming_remote_addr):
    outgoing_sock = None
    try:
        loop = asyncio.get_running_loop()
        
        if DATA_MODE == "tls":
            fake_data = ClientHelloMaker.get_client_hello_with(os.urandom(32), os.urandom(32), FAKE_SNI,
                                                               os.urandom(32))
        else:
            sys.exit("impossible mode!")
            
        outgoing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        outgoing_sock.setblocking(False)
        outgoing_sock.bind((INTERFACE_IPV4, 0))
        outgoing_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        src_port = outgoing_sock.getsockname()[1]
        
        fake_injective_conn = FakeInjectiveConnection(outgoing_sock, INTERFACE_IPV4, CONNECT_IP, src_port, CONNECT_PORT,
                                                      fake_data,
                                                      BYPASS_METHOD, incoming_sock)
        fake_injective_connections[fake_injective_conn.id] = fake_injective_conn
        
        try:
            append_system_log(f"[{fake_injective_conn.id}] Resolving route to {CONNECT_IP}:{CONNECT_PORT}...")
            await loop.sock_connect(outgoing_sock, (CONNECT_IP, CONNECT_PORT))
        except Exception as e:
            append_system_log(f"[{fake_injective_conn.id}] Connection failed: {e}")
            fake_injective_conn.monitor = False
            try:
                del fake_injective_connections[fake_injective_conn.id]
            except KeyError:
                pass
            outgoing_sock.close()
            incoming_sock.close()
            return

        if BYPASS_METHOD == "wrong_seq":
            try:
                await asyncio.wait_for(fake_injective_conn.t2a_event.wait(), 2)
                if fake_injective_conn.t2a_msg == "unexpected_close":
                    raise ValueError("unexpected close during bypass verification")
                elif fake_injective_conn.t2a_msg == "fake_data_ack_recv":
                    append_system_log(f"[{fake_injective_conn.id}] Bypass verification successful.")
                else:
                    sys.exit("impossible t2a msg!")
            except Exception as e:
                append_system_log(f"[{fake_injective_conn.id}] Bypass timeout or verification failed: {e}")
                fake_injective_conn.monitor = False
                try:
                    del fake_injective_connections[fake_injective_conn.id]
                except KeyError:
                    pass
                outgoing_sock.close()
                incoming_sock.close()
                return
        else:
            sys.exit("unknown bypass method!")

        fake_injective_conn.monitor = False
        try:
            del fake_injective_connections[fake_injective_conn.id]
        except KeyError:
            pass

        append_system_log(f"[{incoming_remote_addr}] Active bi-directional data relay streaming.")

        task1 = asyncio.create_task(relay_main_loop_simple(outgoing_sock, incoming_sock, b""))
        task2 = asyncio.create_task(relay_main_loop_simple(incoming_sock, outgoing_sock, b""))
        
        done, pending = await asyncio.wait([task1, task2], return_when=asyncio.FIRST_COMPLETED)
        
        for t in pending:
            t.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    except Exception as e:
        append_system_log(f"Error handling connection from {incoming_remote_addr}: {e}")
    finally:
        if outgoing_sock:
            try:
                outgoing_sock.close()
            except Exception:
                pass
        try:
            incoming_sock.close()
        except Exception:
            pass


async def main_proxy_loop():
    global mother_sock
    mother_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mother_sock.setblocking(False)
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mother_sock.bind((LISTEN_HOST, LISTEN_PORT))
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
    mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
    mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
    mother_sock.listen()
    
    append_system_log(f"[Engine] Listening at {LISTEN_HOST}:{LISTEN_PORT}")
    
    loop = asyncio.get_running_loop()
    while True:
        incoming_sock, addr = await loop.sock_accept(mother_sock)
        incoming_sock.setblocking(False)
        incoming_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
        incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
        incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        asyncio.create_task(handle_connection_task(incoming_sock, addr))


# =====================================================================
# THREAD-SAFE CONTROL HANDLERS (Asynchronous mapping to loop)
# =====================================================================

def start_injector_sync():
    global fake_tcp_injector, injector_thread
    append_system_log("[Engine] Initializing kernel WinDivert capture stack...")
    w_filter = ("tcp and ("
                f"(ip.SrcAddr == {INTERFACE_IPV4} and ip.DstAddr == {CONNECT_IP}) or "
                f"(ip.SrcAddr == {CONNECT_IP} and ip.DstAddr == {INTERFACE_IPV4})"
                ")")
    fake_tcp_injector = FakeTcpInjector(w_filter, fake_injective_connections)
    injector_thread = threading.Thread(target=fake_tcp_injector.run, args=(), daemon=True)
    injector_thread.start()


async def start_engine_coro():
    global proxy_task, is_engine_running, start_time, total_bytes, speed_bytes_last_sec, last_ping_ms
    
    # Reset stats
    total_bytes = 0
    speed_bytes_last_sec = 0
    last_ping_ms = 0
    start_time = time.time()
    
    start_injector_sync()
    proxy_task = asyncio.create_task(main_proxy_loop())
    is_engine_running = True
    append_system_log("[System] Core service started successfully.")


async def stop_engine_coro():
    global proxy_task, mother_sock, fake_tcp_injector, is_engine_running
    
    if proxy_task and not proxy_task.done():
        proxy_task.cancel()
        try:
            await proxy_task
        except asyncio.CancelledError:
            pass
            
    if mother_sock:
        try:
            mother_sock.close()
        except:
            pass
            
    if fake_tcp_injector:
        fake_tcp_injector.stop()
        
    is_engine_running = False
    append_system_log("[System] Core service terminated successfully.")


def stop_engine_sync():
    """Synchronous fallback to terminate active loop components."""
    global is_engine_running, fake_tcp_injector, mother_sock, proxy_task
    is_engine_running = False
    
    if proxy_task:
        try:
            proxy_task.cancel()
        except:
            pass
    if fake_tcp_injector:
        try:
            fake_tcp_injector.stop()
        except:
            pass
    if mother_sock:
        try:
            mother_sock.close()
        except:
            pass


# =====================================================================
# FLASK WEB INTERFACE ENDPOINTS
# =====================================================================

@app.route('/')
def index():
    return send_from_directory(BUNDLE_DIR, 'index.html')


@app.route('/api/config', methods=['GET', 'POST'])
def config_api():
    global LISTEN_HOST, LISTEN_PORT, CONNECT_IP, CONNECT_PORT, FAKE_SNI, INTERFACE_IPV4
    
    if request.method == 'POST':
        data = request.json
        write_config(data)
        
        # Parse connection configs
        listen_val = data.get('listen', '127.0.0.1:40443')
        connect_val = data.get('connect', '104.19.229.21:443')
        
        if ':' in listen_val:
            LISTEN_HOST, port_str = listen_val.rsplit(':', 1)
            LISTEN_PORT = int(port_str)
        else:
            LISTEN_HOST = listen_val
            LISTEN_PORT = 40443
            
        if ':' in connect_val:
            CONNECT_IP, port_str = connect_val.rsplit(':', 1)
            CONNECT_PORT = int(port_str)
        else:
            CONNECT_IP = connect_val
            CONNECT_PORT = 443
            
        FAKE_SNI = data.get('fake-sni', 'hcaptcha.com').encode()
        INTERFACE_IPV4 = get_default_interface_ipv4(CONNECT_IP)
        
        return jsonify({"status": "success", "message": "Configuration saved"})
        
    config_data = read_config()
    return jsonify(config_data)


@app.route('/api/status', methods=['GET'])
def status_api():
    is_running = is_engine_running
    metrics = None
    
    if is_running:
        # Calculate session duration stopwatch
        elapsed = int(time.time() - start_time) if start_time else 0
        hrs = elapsed // 3600
        mins = (elapsed % 3600) // 60
        secs = elapsed % 60
        duration_str = f"{hrs:02d}:{mins:02d}:{secs:02d}"
        
        metrics = {
            "target": CONNECT_IP,
            "ping": last_ping_ms if last_ping_ms > 0 else "N/A",
            "speed": format_speed(speed_kb_s),
            "volume": format_volume(total_bytes),
            "duration": duration_str
        }
        
    return jsonify({"running": is_running, "metrics": metrics})


@app.route('/api/start', methods=['POST'])
def start_api():
    global is_engine_running, INTERFACE_IPV4
    if not is_engine_running:
        # Resolve the outbound physical interface on startup
        INTERFACE_IPV4 = get_default_interface_ipv4(CONNECT_IP)
        if not INTERFACE_IPV4:
            return jsonify({"status": "error", "message": "No interface gateway IP found. Check network connection."}), 400
            
        future = asyncio.run_coroutine_threadsafe(start_engine_coro(), async_loop)
        try:
            future.result(timeout=5)  # Wait for thread safety assignment to execute
            return jsonify({"status": "success", "message": "Service started successfully"})
        except Exception as e:
            return jsonify({"status": "error", "message": f"Startup failure: {e}"}), 500
            
    return jsonify({"status": "error", "message": "Service is already running"})


@app.route('/api/stop', methods=['POST'])
def stop_api():
    global is_engine_running
    if is_engine_running:
        future = asyncio.run_coroutine_threadsafe(stop_engine_coro(), async_loop)
        try:
            future.result(timeout=5)
            return jsonify({"status": "success", "message": "Service stopped"})
        except Exception as e:
            return jsonify({"status": "error", "message": f"Teardown failure: {e}"}), 500
            
    return jsonify({"status": "error", "message": "Service is not running"})


@app.route('/api/logs', methods=['GET'])
def logs_api():
    with log_lock:
        logs_list = list(log_buffer)
    return jsonify({"logs": logs_list})


@app.route('/api/logs/clear', methods=['POST'])
def clear_logs_api():
    with log_lock:
        log_buffer.clear()
        log_buffer.append("[System] Log buffer cleared.")
    return jsonify({"status": "success"})


@app.route('/api/check_update', methods=['GET'])
def check_update_api():
    url = "https://api.github.com/repos/GMH84/SNI-Spoofing-UI/releases/latest"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            import json
            data = json.loads(response.read().decode('utf-8'))
            tag_name = data.get("tag_name", "").strip()
            latest_version = tag_name.lstrip('v')
            download_url = data.get("html_url", "")
            
            if not latest_version:
                return jsonify({"status": "error", "message": "Failed to parse release tags from GitHub."})
                
            update_available = (latest_version != CURRENT_VERSION)
            return jsonify({
                "status": "success",
                "current_version": CURRENT_VERSION,
                "latest_version": latest_version,
                "download_url": download_url,
                "update_available": update_available
            })
    except urllib.error.URLError as e:
        return jsonify({"status": "error", "message": f"Connection lost: {str(e.reason)}"})
    except Exception as e:
        return jsonify({"status": "error", "message": f"Server check error: {str(e)}"})


@app.route('/api/open_browser', methods=['POST'])
def open_browser_api():
    url = request.args.get('url')
    if url:
        webbrowser.open(url)
        return jsonify({"status": "success"})
    return jsonify({"status": "error", "message": "No download target provided."}), 400


# =====================================================================
# WINDOW SYSTEM PRIVILEGES & LIFECYCLE
# =====================================================================

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


class WindowControls:
    def minimize(self):
        active_window = webview.active_window()
        if active_window:
            active_window.minimize()

    def close(self):
        stop_engine_sync()
        active_window = webview.active_window()
        if active_window:
            active_window.destroy()
        sys.exit(0)


def start_asyncio_loop(loop):
    asyncio.set_event_loop(loop)
    loop.run_forever()


if __name__ == '__main__':
    # Force Administrative Privilege Elevation on Windows to run WinDivert Capture
    if os.name == 'nt' and not is_admin():
        if getattr(sys, 'frozen', False):
            executable = sys.executable
            args = ""
        else:
            executable = sys.executable
            args = f'"{os.path.abspath(__file__)}"'
            
        ctypes.windll.shell32.ShellExecuteW(
            None, 
            "runas", 
            executable, 
            args, 
            CURRENT_DIR, 
            1
        )
        sys.exit()

    # Pre-parse engine configuration definitions on load
    config_data = read_config()
    listen_val = config_data.get('listen', '127.0.0.1:40443')
    connect_val = config_data.get('connect', '104.19.229.21:443')
    
    if ':' in listen_val:
        LISTEN_HOST, port_str = listen_val.rsplit(':', 1)
        LISTEN_PORT = int(port_str)
    else:
        LISTEN_HOST = listen_val
        LISTEN_PORT = 40443
        
    if ':' in connect_val:
        CONNECT_IP, port_str = connect_val.rsplit(':', 1)
        CONNECT_PORT = int(port_str)
    else:
        CONNECT_IP = connect_val
        CONNECT_PORT = 443
        
    FAKE_SNI = config_data.get('fake-sni', 'hcaptcha.com').encode()
    INTERFACE_IPV4 = get_default_interface_ipv4(CONNECT_IP)

    # Boot the async loop worker thread 
    async_loop = asyncio.new_event_loop()
    async_thread = threading.Thread(target=start_asyncio_loop, args=(async_loop,), daemon=True)
    async_thread.start()

    # Initialize Pywebview Interface Frame
    controls = WindowControls()

    window = webview.create_window(
        title='SNI Spoofing Control', 
        url=app, 
        width=400, 
        height=680, 
        resizable=False,
        frameless=True,
        easy_drag=False,
        js_api=controls,
        background_color='#06060c'
    )
    
    webview.start()
