#!/usr/bin/env python3
"""Simple deterministic TCP proxy with optional latency/jitter/drop simulation.

This is intentionally lightweight and dependency-free so it can run in CI and
on macOS without Linux traffic-control tooling.
"""

from __future__ import annotations

import argparse
import asyncio
import random
import signal
from typing import Optional


class NetemProxy:
    def __init__(
        self,
        listen_host: str,
        listen_port: int,
        target_host: str,
        target_port: int,
        latency_ms: float,
        jitter_ms: float,
        drop_percent: float,
        seed: int,
    ) -> None:
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.latency_ms = max(0.0, latency_ms)
        self.jitter_ms = max(0.0, jitter_ms)
        self.drop_percent = max(0.0, min(100.0, drop_percent))
        self._rng = random.Random(seed)
        self._server: Optional[asyncio.base_events.Server] = None

    def _delay_seconds(self) -> float:
        # Symmetric jitter around base latency with clamp at 0.
        jitter = self._rng.uniform(-self.jitter_ms, self.jitter_ms) if self.jitter_ms else 0.0
        return max(0.0, (self.latency_ms + jitter) / 1000.0)

    def _should_drop(self) -> bool:
        if self.drop_percent <= 0.0:
            return False
        return self._rng.random() < (self.drop_percent / 100.0)

    async def _pipe(self, src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
        try:
            while True:
                data = await src.read(4096)
                if not data:
                    break
                if self._should_drop():
                    # Drop this chunk and continue forwarding subsequent chunks.
                    continue
                delay = self._delay_seconds()
                if delay > 0:
                    await asyncio.sleep(delay)
                dst.write(data)
                await dst.drain()
        except (asyncio.CancelledError, ConnectionError, OSError):
            pass
        finally:
            try:
                dst.close()
                await dst.wait_closed()
            except Exception:
                pass

    async def _handle_client(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(self.target_host, self.target_port)
        except Exception:
            try:
                client_writer.close()
                await client_writer.wait_closed()
            except Exception:
                pass
            return

        t1 = asyncio.create_task(self._pipe(client_reader, upstream_writer))
        t2 = asyncio.create_task(self._pipe(upstream_reader, client_writer))
        done, pending = await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        for task in done:
            try:
                await task
            except Exception:
                pass

    async def run(self) -> None:
        self._server = await asyncio.start_server(self._handle_client, self.listen_host, self.listen_port)
        addrs = ", ".join(str(sock.getsockname()) for sock in (self._server.sockets or []))
        print(
            f"[netem-proxy] listening on {addrs} -> {self.target_host}:{self.target_port} "
            f"latency={self.latency_ms}ms jitter={self.jitter_ms}ms drop={self.drop_percent}%"
        )
        async with self._server:
            await self._server.serve_forever()


async def main_async(args: argparse.Namespace) -> None:
    proxy = NetemProxy(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        target_host=args.target_host,
        target_port=args.target_port,
        latency_ms=args.latency_ms,
        jitter_ms=args.jitter_ms,
        drop_percent=args.drop_percent,
        seed=args.seed,
    )
    await proxy.run()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Deterministic TCP network-emulation proxy")
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, required=True)
    parser.add_argument("--target-host", default="127.0.0.1")
    parser.add_argument("--target-port", type=int, required=True)
    parser.add_argument("--latency-ms", type=float, default=0.0)
    parser.add_argument("--jitter-ms", type=float, default=0.0)
    parser.add_argument("--drop-percent", type=float, default=0.0)
    parser.add_argument("--seed", type=int, default=1337)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, loop.stop)
        except NotImplementedError:
            pass
    try:
        loop.run_until_complete(main_async(args))
    finally:
        loop.close()


if __name__ == "__main__":
    main()
