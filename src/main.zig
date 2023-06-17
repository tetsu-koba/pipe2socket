const std = @import("std");
const log = std.log;
const mem = std.mem;
const os = std.os;
const time = std.time;

const MAX_EVENT = 5;
var running: bool = false;

fn createSignalfd() !os.fd_t {
    var mask = os.empty_sigset;
    os.linux.sigaddset(&mask, os.linux.SIG.INT);
    os.linux.sigaddset(&mask, os.linux.SIG.TERM);
    _ = os.linux.sigprocmask(os.linux.SIG.BLOCK, &mask, null);
    return try os.signalfd(-1, &mask, os.linux.SFD.CLOEXEC);
}

fn handleSignals(signal_fd: os.fd_t) !void {
    var buf: [@sizeOf(os.linux.signalfd_siginfo)]u8 align(8) = undefined;
    if (buf.len != try os.read(signal_fd, &buf)) {
        return os.ReadError.InputOutput;
    }
    const info = @ptrCast(*os.linux.signalfd_siginfo, &buf);
    switch (info.signo) {
        os.linux.SIG.INT => {
            log.info("{d}:Got SIGINT", .{time.milliTimestamp()});
            running = false;
        },
        os.linux.SIG.TERM => {
            log.info("{d}:Got SIGTERM", .{time.milliTimestamp()});
            running = false;
        },
        else => unreachable,
    }
}

fn frameHandler(tcp: std.net.Stream, buf: []u8) void {
    const fd = os.linux.STDIN_FILENO;
    const n = os.read(fd, buf) catch |err| {
        log.err("frameHandle: {s}", .{@errorName(err)});
        running = false;
        return;
    };
    if (n == 0) {
        running = false;
        return;
    }
    tcp.writeAll(buf[0..n]) catch |err| {
        log.err("frameHandle: {s}", .{@errorName(err)});
        running = false;
    };
}

fn open(alc: mem.Allocator, url_string: []const u8) !std.net.Stream {
    const uri = try std.Uri.parse(url_string);
    if (mem.eql(u8, uri.scheme, "tcp")) {
        if (uri.host) |host| {
            if (uri.port) |port| {
                return std.net.tcpConnectToHost(alc, host, port);
            }
        }
    }
    return error.InvalidURL;
}

// Check if the given file descriptor is a pipe
pub fn isPipe(fd: os.fd_t) !bool {
    var stat: os.linux.Stat = undefined;
    if (0 != os.linux.fstat(fd, &stat)) {
        return error.Fstat;
    }
    return (stat.mode & os.linux.S.IFMT) == os.linux.S.IFIFO;
}

// Get the max size pipe
pub fn getPipeMaxSize() !usize {
    var pipe_max_size_file = try std.fs.cwd().openFile("/proc/sys/fs/pipe-max-size", .{});
    defer pipe_max_size_file.close();

    var reader = pipe_max_size_file.reader();
    var buffer: [128]u8 = undefined;
    const max_size_str = std.mem.trimRight(u8, buffer[0..(try reader.readAll(&buffer))], &std.ascii.whitespace);
    const max_size = std.fmt.parseInt(usize, max_size_str, 10) catch |err| {
        std.debug.print("Failed to parse /proc/sys/fs/pipe-max-size: {}\n", .{err});
        return err;
    };
    return max_size;
}

pub fn main() !void {
    const alc = std.heap.page_allocator;
    const args = try std.process.argsAlloc(alc);
    defer std.process.argsFree(alc, args);

    if (args.len < 2) {
        std.debug.print("Usage: {s} URL\nURL is 'tcp://hostname:port'\n", .{args[0]});
        os.exit(1);
    }
    const url_string = args[1];
    if (!try isPipe(os.linux.STDIN_FILENO)) {
        std.debug.print("stdin must be pipe\n", .{});
        os.exit(1);
    }

    const tcp = try open(alc, url_string);
    defer tcp.close();

    const epoll_fd = try os.epoll_create1(os.linux.EPOLL.CLOEXEC);
    defer os.close(epoll_fd);
    var read_event = os.linux.epoll_event{
        .events = os.linux.EPOLL.IN,
        .data = os.linux.epoll_data{ .fd = os.linux.STDIN_FILENO },
    };
    try os.epoll_ctl(epoll_fd, os.linux.EPOLL.CTL_ADD, read_event.data.fd, &read_event);

    const signal_fd = try createSignalfd();
    defer os.close(signal_fd);
    var signal_event = os.linux.epoll_event{
        .events = os.linux.EPOLL.IN,
        .data = os.linux.epoll_data{ .fd = signal_fd },
    };
    try os.epoll_ctl(epoll_fd, os.linux.EPOLL.CTL_ADD, signal_event.data.fd, &signal_event);
    const timeout = 5000;
    const pipe_max_size = try getPipeMaxSize();
    var buf = try alc.alloc(u8, pipe_max_size);
    defer alc.free(buf);
    running = true;
    while (running) {
        var events: [MAX_EVENT]os.linux.epoll_event = .{};
        const event_count = os.epoll_wait(epoll_fd, &events, timeout);
        if (event_count == 0) {
            log.info("{d}:timeout", .{time.milliTimestamp()});
            continue;
        }
        for (events[0..event_count]) |ev| {
            if (ev.data.fd == read_event.data.fd) {
                frameHandler(tcp, buf);
            } else if (ev.data.fd == signal_event.data.fd) {
                try handleSignals(signal_event.data.fd);
            } else {
                unreachable;
            }
        }
    }
}
