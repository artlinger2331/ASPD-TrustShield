import asyncio
print("1. Getting loop...", flush=True)
loop = asyncio.new_event_loop()
print("2. Loop created:", loop, flush=True)
async def hello():
    print("In hello()", flush=True)
    return 42

res = loop.run_until_complete(hello())
print("3. Result:", res, flush=True)
loop.close()
print("4. Done!", flush=True)
