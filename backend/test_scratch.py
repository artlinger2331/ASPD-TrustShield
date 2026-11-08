import sys, asyncio
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

async def f():
    print("HELLO ASYNCIO", flush=True)

asyncio.run(f())
