# Taken from megadlbot_oss <https://github.com/eyaadh/megadlbot_oss/blob/master/mega/webserver/routes.py>
# Thanks to Eyaadh <https://github.com/eyaadh>

import pyrogram
import re
import time, asyncio, json
import math
import logging
import secrets, utils
from os import getenv
import mimetypes
from aiohttp.web import Request
from typing import Union
from aiohttp import web
from aiohttp.http_exceptions import BadStatusLine
from streamer.exceptions import *
from utils.constants import work_loads

logger = logging.getLogger("routes")
StartTime = time.time()

routes = web.RouteTableDef()


@routes.get("/", allow_head=True)
async def root_route_handler(_):
    return web.json_response(
        {
            "server_status": "running",
            "uptime": utils.get_readable_time(time.time() - StartTime),
            "loads": dict(
                ("bot" + str(c + 1), l)
                for c, (_, l) in enumerate(
                    sorted(work_loads.items(), key=lambda x: x[1], reverse=True)
                )
            ),
        }
    )


@routes.get(r"/stream", allow_head=True)
async def stream_handler(request: web.Request):
    return await __stream_handler(request)


@routes.get(r"/thumb", allow_head=True)
async def stream_handler(request: web.Request):
    return await __stream_handler(request, True)


async def __stream_handler(request: web.Request, thumb=False):
    try:
        channel = request.query.get("channel")
        try:
            channel = int(channel)
        except Exception as er:
            pass
        messageId = int(request.query.get("messageId"))
        return await media_streamer(request, channel, messageId, thumb)
    except InvalidHash as e:
        raise web.HTTPForbidden(text=e.message)
    except FIleNotFound as e:
        raise web.HTTPNotFound(text=e.message)
    except (AttributeError, BadStatusLine, ConnectionResetError):
        pass
    except Exception as e:
        logger.critical(str(e), exc_info=True)
        raise web.HTTPInternalServerError(text=str(e))


class_cache = {}


async def media_streamer(
    request: web.Request,
    channel: Union[str, int],
    message_id: int,
    thumb: bool = False,
):
    from bot import bot
    range_header = request.headers.get("Range", 0)

    index = min(work_loads, key=work_loads.get)
    if not class_cache.get(0):
        class_cache[0] = utils.ByteStreamer(bot)

    try:
        msg = await bot.get_messages(channel, message_ids=message_id)
        assert msg != None
        faster_client = bot
        tg_connect = class_cache[0]
    except Exception as er:
        logger.info(f"check tgbot access: {er}")
        return web.json_response({"message": str(er), "ok": False})

        #    if Var.MULTI_CLIENT:
        #        logger.info(f"Client {index} is now serving {request.remote}")

        if class_cache.get(userid):
            tg_connect = class_cache[userid]
            logger.debug(f"Using cached ByteStreamer object for client {userid}")
        else:
            logger.debug(f"Creating new ByteStreamer object for client {userid}")
            tg_connect = utils.ByteStreamer(faster_client)
            class_cache[userid] = tg_connect

    logger.debug("before calling get_file_properties")
    file_id = await tg_connect.get_file_properties(channel, message_id, thumb)
    #    print(file_id, thumb)
    logger.debug("after calling get_file_properties")

    #    if utils.get_hash(file_id.unique_id, 7) != secure_hash:
    #       logger.debug(f"Invalid hash for message with ID {message_id}")
    #      raise InvalidHash

    file_size = file_id.file_size

    if range_header:
        from_bytes, until_bytes = range_header.replace("bytes=", "").split("-")
        from_bytes = int(from_bytes)
        until_bytes = int(until_bytes) if until_bytes else file_size - 1
    else:
        from_bytes = request.http_range.start or 0
        until_bytes = (request.http_range.stop or file_size) - 1

    if (until_bytes > file_size) or (from_bytes < 0) or (until_bytes < from_bytes):
        return web.Response(
            status=416,
            body="416: Range not satisfiable",
            headers={"Content-Range": f"bytes */{file_size}"},
        )

    chunk_size = 1024 * 1024
    until_bytes = min(until_bytes, file_size - 1)

    offset = from_bytes - (from_bytes % chunk_size)
    first_part_cut = from_bytes - offset
    last_part_cut = until_bytes % chunk_size + 1

    req_length = until_bytes - from_bytes + 1
    part_count = math.ceil(until_bytes / chunk_size) - math.floor(offset / chunk_size)
    body = tg_connect.yield_file(
        file_id, index, offset, first_part_cut, last_part_cut, part_count, chunk_size
    )
    mime_type = file_id.mime_type
    file_name = utils.get_name(file_id)
    print(file_name, mime_type, file_id)
    disposition = "attachment"

    if not mime_type:
        mime_type = mimetypes.guess_type(file_name)[0] or "application/octet-stream"

    if "video/" in mime_type or "audio/" in mime_type or "/html" in mime_type:
        disposition = "inline"

    return web.Response(
        status=206 if range_header else 200,
        body=body,
        headers={
            "Content-Type": str(mime_type),
            "Content-Range": f"bytes {from_bytes}-{until_bytes}/{file_size}",
            "Content-Length": str(req_length),
            "Content-Disposition": f'{disposition}; filename="{file_name}"',
            "Accept-Ranges": "bytes",
        },
    )

APP_AUTH_TOKEN = getenv("APP_AUTH_TOKEN", "")

def notVerified(request: Request):
    headers = request.headers
    if APP_AUTH_TOKEN and headers.get("Authorization") != APP_AUTH_TOKEN:
        return web.json_response({"ok": False, "message": "UNAUTHORIZED"})
    return



@routes.get("/tasks")
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
    return web.json_response({"ok": True, "tasks": tasks})


@routes.get("/task")
async def getTaskDetail(request: Request):
    if notVerified(request):
        return

    from bot.helper.ext_utils.bot_utils import getDownloadByGid
    from bot.helper.mirror_utils.status_utils.aria2_status import Aria2Status
    from bot.helper.listeners.tasks_listener import MirrorLeechListener
    id = request.query.get("id")
    if not id:
        return web.json_response({"ok": False, "message": "INVALID_REQUEST"})

    task: Aria2Status = await getDownloadByGid(id)
    if not task:
        return web.json_response({"ok": False, "message": "Task not found!"})
    try:
        listener: MirrorLeechListener = task.listener()
    except AttributeError:
        listener = None

#    print(task)
    return web.json_response({
        "name": task.name(),
        "speed": task.speed(),
        "eta": task.eta(),
        "link": task.listener().source_url if listener else None,
        "progress": task.progress(),
        "processed_bytes": task.processed_bytes(),
        "queued": task.queued if hasattr(task, "queued") else None,
        "size": task.size(),
        "start_time": task.start_time if hasattr(task, "start_time") else None,
        "status": task.status(),
        "user_id": task.message.from_user.id,
        "username": task.message.from_user.username,
        "sender_name": task.message.from_user.first_name,
        "uid": listener.uid
    })

@routes.get("/result")
async def getResult(request: web.Request):
    from bot import taskHolder

    uid = request.query.get("uid")
    result = taskHolder.get(int(uid), {})
    return web.json_response({"results": result})

@routes.post("/cancelTask/{id}")
async def cancelTask(request: Request):
    if notVerified(request):
        return
    # TODO: Implement Cancel from GID


@routes.get("/success")
async def showThankPage(request: Request):
    return web.FileResponse(
        path="streamer/login.html"
    )

BIND_ADDRESS = getenv("API_BASE_URL", "http://127.0.0.1")
PORT_URL = int(getenv("API_URL_PORT", 2666))

@routes.get("/login")
async def redirect(request: Request):
    from bot import bot
    bot_id = (await bot.get_me()).id
    url = f"{BIND_ADDRESS}:{PORT_URL}"

    return web.HTTPFound(
        f"https://oauth.telegram.org/auth?bot_id={bot_id}&origin={url}&request_access=write&return_to={url}/success"
    )

@routes.get("/files")
async def getUserHistory(request: Request):
    if notVerified(request):
        return
    userId = request.query.get("userId")
    if not userId:
        return web.json_response({
            "ok": False,
            "message": "INVALID_REQUEST"
        })
    from bot.helper.ext_utils.db_handler import DbManger, DATABASE_URL
    if not DATABASE_URL:
        return web.json_response({"ok": False,
                                  "message": "NOT_AVAILABLE"})
    history = await DbManger().get_user_history(
        int(userId)
    )
    return web.json_response(history)


@routes.get("/messageInfo")
async def getMessage(
    request: Request
):
    if notVerified(request):
        return

    from bot import bot

    channel = request.query.get("channel")
    try:
        msgId = int(request.query.get("messageId"))
    except Exception:
        return web.json_response({"ok": False, "message": "INVALID_RESPONSE"})
    try:
        channel = int(channel)
    except Exception:
        pass
    message = await bot.get_messages(
        chat_id=channel, message_ids=msgId
    )
    return web.json_response(json.loads(str(message)))