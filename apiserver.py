from os import getenv
from dotenv import load_dotenv

from fastapi import FastAPI, Request
from fastapi.responses import Response

load_dotenv("config.env")

APP_AUTH_TOKEN = getenv("APP_AUTH_TOKEN", "")
app = FastAPI()

def notVerified(request: Request):
    headers = request.headers
    if APP_AUTH_TOKEN and headers.get("Authorization") != APP_AUTH_TOKEN:
        return {"ok": False, "message": "UNAUTHORIZED"}
    return

@app.get("/")
async def getRoot(request: Request):
    from bot import botStartTime

    if notVerified(request):
        return
    return {"ok": True, "uptime": botStartTime}


@app.get("/tasks")
async def getTasks(request: Request):
    from bot import download_dict
    from bot.helper.mirror_utils.status_utils.aria2_status import Aria2Status

    if notVerified(request):
        return
    tasks = []
    for task in download_dict.values():
        task: Aria2Status
        tasks.append(
            {
                "gid": task.gid(),
                "name": task.name(),
                "queued": task.queued if hasattr(task, "queued") else None,
                 "size": task.size(),
                "progress": task.progress(),
                "processed_bytes": task.processed_bytes(),
                "eta": task.eta(),
                "status": task.status(),
                "leechers_num": task.leechers_num() if hasattr(task, "leechers_num") else None,
                "seeders_num": task.seeders_num() if hasattr(task, "seeders_num") else None
            }
        )
    print(download_dict)
    return {"ok": True, "tasks": tasks}


@app.get("/task/{id}")
async def getTaskDetail(id: str, request: Request):
    if notVerified(request):
        return
    from bot.helper.ext_utils.bot_utils import getDownloadByGid
    from bot.helper.mirror_utils.status_utils.aria2_status import Aria2Status
    from bot.helper.listeners.tasks_listener import MirrorLeechListener

    task: Aria2Status = await getDownloadByGid(id)
    if not task:
        return {"ok": False, "message": "Task not found!"}
    try:
        listener: MirrorLeechListener = task.listener()
    except AttributeError:
        listener = None

#    print(task)
    return {
        "name": task.name(),
        "speed": task.speed(),
        "eta": task.eta(),
        "link": task.listener().source_url if listener else None,
        "progress": task.progress(),
        "processed_bytes": task.processed_bytes(),
        "queued": task.queued if hasattr(task, "queued") else None,
        "size": task.size(),
        "start_time": task.start_time,
        "status": task.status(),
        "user_id": task.message.from_user.id,
        "username": task.message.from_user.username,
        "name": task.message.from_user.first_name
    }

