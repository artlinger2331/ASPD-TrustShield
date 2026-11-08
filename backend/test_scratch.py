def run_coro(coro):
    """Executes a coroutine that wraps synchronous/fallback operations without creating an asyncio event loop."""
    try:
        while True:
            coro.send(None)
    except StopIteration as e:
        return e.value

async def inner():
    return 100

async def outer():
    val = await inner()
    return val + 42

result = run_coro(outer())
print("RESULT:", result, flush=True)
