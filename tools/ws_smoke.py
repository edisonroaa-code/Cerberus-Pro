import asyncio
import websockets


async def main() -> None:
    # Integration smoke test (requires backend running).
    # Kept out of pytest collection to avoid flaky CI/local runs.
    uri = "ws://127.0.0.1:8001/ws?token=dev_token_bypass"
    try:
        async with websockets.connect(
            uri, extra_headers=[("Origin", "http://localhost:5173")]
        ) as ws:
            print("connected")
            await ws.send("ping")
            await asyncio.sleep(1)
    except Exception as e:
        print("connect error:", type(e), e)


if __name__ == "__main__":
    asyncio.run(main())

