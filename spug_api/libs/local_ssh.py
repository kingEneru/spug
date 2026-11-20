# Copyright: (c) OpenSpug Organization. https://github.com/openspug/spug
# Copyright: (c) <spug.dev@gmail.com>
# Released under the AGPL-3.0 License.
"""
本机执行器：让 Spug 把 Spug 服务自身所在的机器（容器 / Pod）当作一台目标主机。

LocalSSH 继承 SSH，只把 paramiko 的 SSHClient 换成本地实现（LocalClient），
因此 exec_command / exec_command_with_stream / get_pid / terminate 等协议逻辑与远程主机完全一致：
- invoke_shell -> 在伪终端（pty）里启动登录 shell，供批量执行、发布、Web 终端使用
- get_transport().open_session() -> 本地 subprocess，供 exec_command_raw 使用
- open_sftp -> 直接读写本地文件系统，供文件管理、文件上传使用
"""
from paramiko.sftp_attr import SFTPAttributes
from libs.ssh import SSH
import subprocess
import getpass
import select
import shutil
import socket
import struct
import fcntl
import errno
import os
import pty
import termios
import signal

# 主机地址填写该值时视为本机，不走 SSH
LOCAL_HOSTNAME = 'local'


def is_local_hostname(hostname):
    return (hostname or '').strip() == LOCAL_HOSTNAME


def new_ssh(hostname, port=22, username='root', pkey=None, password=None, default_env=None, **kwargs):
    """按主机地址返回远程 SSH 或本机执行器，参数与 SSH 一致"""
    if is_local_hostname(hostname):
        return LocalSSH(default_env=default_env, term=kwargs.get('term'))
    return SSH(hostname, port, username, pkey, password, default_env=default_env, **kwargs)


def _get_shell():
    # 优先 bash：发布/执行脚本通常按 Linux 主机编写；zsh 的交互提示符（如 PROMPT_SP）还会混入输出
    return shutil.which('bash') or os.environ.get('SHELL') or '/bin/sh'


def _set_ctty():
    # 在子进程中执行（setsid 之后）：把 pty 设为控制终端，Ctrl+C 等信号与作业控制才会生效
    try:
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    except OSError:
        pass


def _kill_group(proc):
    if proc.poll() is None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


class _LocalTransport:
    remote_version = 'SSH-2.0-SpugLocal'

    def __init__(self, client):
        self.client = client

    def open_session(self):
        session = _LocalSession()
        self.client.add_resource(session)
        return session

    def set_keepalive(self, interval):
        pass


class _LocalSession:
    """对应 paramiko 的 exec 通道：一次性执行命令并读取合并后的输出"""

    def __init__(self):
        self.proc = None

    def set_combine_stderr(self, combine):
        pass

    def exec_command(self, command):
        self.proc = subprocess.Popen(
            [_get_shell(), '-c', command],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=os.path.expanduser('~'),
            start_new_session=True,
        )

    def recv(self, size):
        return self.proc.stdout.read1(size)

    def recv_exit_status(self):
        return self.proc.wait()

    def close(self):
        if self.proc:
            _kill_group(self.proc)
            self.proc.stdout.close()


class _LocalChannel:
    """对应 paramiko 的交互式 shell 通道，基于伪终端实现"""

    def __init__(self, term='xterm', width=80, height=24, **kwargs):
        self.timeout = None
        self.closed = False
        self.transport = _LocalTransport(None)
        master, slave = pty.openpty()
        self._set_winsize(slave, width, height)
        env = dict(os.environ, TERM=term or 'xterm')
        try:
            self.proc = subprocess.Popen(
                [_get_shell(), '-l'],
                stdin=slave,
                stdout=slave,
                stderr=slave,
                env=env,
                cwd=os.path.expanduser('~'),
                start_new_session=True,
                preexec_fn=_set_ctty,
            )
        except Exception:
            os.close(master)
            raise
        finally:
            os.close(slave)
        self.fd = master

    @staticmethod
    def _set_winsize(fd, width, height):
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', int(height), int(width), 0, 0))

    def settimeout(self, timeout):
        self.timeout = timeout

    def recv_ready(self):
        if self.closed:
            return False
        readable, _, _ = select.select([self.fd], [], [], 0)
        return bool(readable)

    def recv(self, size):
        if self.closed:
            return b''
        readable, _, _ = select.select([self.fd], [], [], self.timeout)
        if not readable:
            raise socket.timeout()
        try:
            return os.read(self.fd, size)
        except OSError as e:
            # shell 退出后读 master 端会返回 EIO，等同于通道关闭
            if e.errno in (errno.EIO, errno.EBADF):
                return b''
            raise

    def sendall(self, data):
        if self.closed:
            raise OSError('channel is closed')
        if isinstance(data, str):
            data = data.encode()
        view = memoryview(data)
        while view:
            written = os.write(self.fd, view)
            view = view[written:]

    def resize_pty(self, width=80, height=24, *args, **kwargs):
        if not self.closed:
            self._set_winsize(self.fd, width, height)

    def close(self):
        if self.closed:
            return
        self.closed = True
        _kill_group(self.proc)
        try:
            os.close(self.fd)
        except OSError:
            pass


class _LocalSFTP:
    """对应 paramiko 的 SFTPClient，仅实现 Spug 用到的方法"""

    def put(self, localpath, remotepath, callback=None, confirm=True):
        total = os.stat(localpath).st_size
        with open(localpath, 'rb') as fl:
            return self.putfo(fl, remotepath, total, callback, confirm)

    def putfo(self, fl, remotepath, file_size=0, callback=None, confirm=True):
        size = 0
        with open(remotepath, 'wb') as fr:
            while True:
                data = fl.read(32768)
                if not data:
                    break
                if isinstance(data, str):
                    data = data.encode()
                fr.write(data)
                size += len(data)
                if callback is not None:
                    callback(size, file_size)
        return self.stat(remotepath)

    def listdir_attr(self, path='.'):
        result = []
        for name in os.listdir(path):
            try:
                st = os.lstat(os.path.join(path, name))
            except FileNotFoundError:
                continue
            result.append(SFTPAttributes.from_stat(st, name))
        return result

    def stat(self, path):
        return SFTPAttributes.from_stat(os.stat(path), os.path.basename(path))

    def open(self, filename, mode='r', bufsize=-1):
        if 'b' not in mode:
            mode += 'b'
        return open(filename, mode)

    def remove(self, path):
        os.remove(path)

    def chmod(self, path, mode):
        os.chmod(path, mode)

    def close(self):
        pass


class LocalClient:
    """对应 paramiko 的 SSHClient；close 时回收所有由它启动的进程"""

    def __init__(self):
        self._resources = []

    def add_resource(self, resource):
        self._resources.append(resource)

    def get_transport(self):
        return _LocalTransport(self)

    def invoke_shell(self, term='xterm', width=80, height=24, **kwargs):
        channel = _LocalChannel(term, width, height)
        self.add_resource(channel)
        return channel

    def open_sftp(self):
        return _LocalSFTP()

    def close(self):
        resources, self._resources = self._resources, []
        for item in resources:
            try:
                item.close()
            except Exception:
                pass


class LocalSSH(SSH):
    def __init__(self, default_env=None, term=None, **kwargs):
        super().__init__(LOCAL_HOSTNAME, None, getpass.getuser(), default_env=default_env, term=term)

    def get_client(self):
        if self.client is None:
            self.client = LocalClient()
        return self.client

    def add_public_key(self, public_key):
        # 本机无需 SSH 认证
        pass
