#!/usr/bin/env python3
import os
import re
import fuz_pb2
import json
import argparse
import logging
from getpass import getpass
from urllib.request import Request, urlopen
from google.protobuf import json_format
from threading import Thread
from queue import Queue
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

COOKIE = "is_logged_in=true; fuz_session_key="
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
            " AppleWebKit/537.36 (KHTML, like Gecko)" \
            " Chrome/96.0.4664.55" \
            " Safari/537.36" \
            " Edg/96.0.1054.34"

API_HOST = "https://api.comic-fuz.com"
IMG_HOST = "https://img.comic-fuz.com"
TABLE = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_"
T_MAP = {s: i for i, s in enumerate(TABLE)}

def sign(email: str, password: str) -> str:
    body = fuz_pb2.SignInRequest()
    body.deviceInfo.deviceType = fuz_pb2.DeviceInfo.DeviceType.BROWSER
    body.email = email
    body.password = password
    url = API_HOST + "/v1/sign_in"
    req = Request(url, body.SerializeToString(), method="POST")
    with urlopen(req) as r:
        res = fuz_pb2.SignInResponse()
        res.ParseFromString(r.read())
        if not res.success:
            logging.error("Login failed")
            exit(1)
        for header in r.headers:
            m = re.match(r'token=(\w+)(;.*)?', r.headers[header])
            if m:
                return m.group(1)

def check_sign(token: str) -> bool:
    url = API_HOST + "/v1/web_mypage"
    headers = {
        "user-agent": USER_AGENT,
        "cookie": COOKIE + token
    }
    req = Request(url, headers=headers, method="POST")
    with urlopen(req) as r:
        res = fuz_pb2.WebMypageResponse()
        res.ParseFromString(r.read())
        if res.mailAddress:
            logging.info("Login as: %s", res.mailAddress)
            return True
        return False

def get_session(file: str, user: str, pwd: str) -> str:
    if not file and not user:
        logging.info("Disable login, get only free part.")
        return ""
    if file and os.path.exists(file):
        with open(file) as f:
            token = f.read().strip()
        if check_sign(token):
            return token
        logging.debug("Get failed, try signing")
    user = user if user else input("Email: ")
    pwd = pwd if pwd else getpass("Password: ")
    token = sign(user, pwd)
    with open(file, "w") as f:
        f.write(token)
    return token

def b64_to_10(s: str) -> int:
    i = 0
    for c in s:
        i = i * 64 + T_MAP[c]
    return i

def get_index(path: str, body: str, token: str) -> str:
    url = API_HOST + path
    headers = { "user-agent": USER_AGENT }
    if token:
        headers["cookie"] = COOKIE + token
    req = Request(url, body, headers, method="POST")
    with urlopen(req) as r:
        return r.read()

def get_book_index(bookId: int, token: str) -> fuz_pb2.BookViewer2Response:
    body = fuz_pb2.BookViewer2Request()
    body.deviceInfo.deviceType = fuz_pb2.DeviceInfo.DeviceType.BROWSER
    body.bookIssueId = bookId
    body.viewerMode.imageQuality = fuz_pb2.ViewerMode.ImageQuality.HIGH

    res = get_index("/v1/book_viewer_2", body.SerializeToString(), token)
    index = fuz_pb2.BookViewer2Response()
    index.ParseFromString(res)
    return index

def get_magazine_index(magazineId: int, token: str) -> fuz_pb2.MagazineViewer2Response:
    body = fuz_pb2.MagazineViewer2Request()
    body.deviceInfo.deviceType = fuz_pb2.DeviceInfo.DeviceType.BROWSER
    body.magazineIssueId = magazineId
    body.viewerMode.imageQuality = fuz_pb2.ViewerMode.ImageQuality.HIGH

    res = get_index("/v1/magazine_viewer_2", body.SerializeToString(), token)
    index = fuz_pb2.MagazineViewer2Response()
    index.ParseFromString(res)
    return index

def get_manga_index(mangaId: int, token: str) -> fuz_pb2.MangaViewerResponse:
    body = fuz_pb2.MangaViewerRequest()
    body.deviceInfo.deviceType = fuz_pb2.DeviceInfo.DeviceType.BROWSER
    body.chapterId = mangaId
    body.viewerMode.imageQuality = fuz_pb2.ViewerMode.ImageQuality.HIGH

    res = get_index("/v1/manga_viewer", body.SerializeToString(), token)
    index = fuz_pb2.MangaViewerResponse()
    index.ParseFromString(res)
    return index

def downloadThumb(save_dir: str, url: str, overwrite=False):
    name = re.match(r'.*/([0-9a-zA-Z_-]+)\.(\w+)\?.*', url)
    if not name or not name.group(1):
        print("Can't gass filename: ", url)
        return
    name = f"{save_dir}{b64_to_10(name.group(1))}.{name.group(2)}"
    if not overwrite and os.path.exists(name):
        return
    with open(name, "wb") as f:
        with urlopen(IMG_HOST + url) as r:
            f.write(r.read())
    # os.system(f"curl -s \"{IMG_HOST}{url}\" -o {name}")

def download(save_dir: str, image: fuz_pb2.ViewerPage.Image, overwrite=False):
    if not image.imageUrl:
        logging.debug("Not an image: %s", image)
        return
    name = re.match(r'.*/([0-9a-zA-Z_-]+)\.(\w+)\.enc\?.*', image.imageUrl)
    if not name or not name.group(1):
        logging.debug("Can't gass filename: %s", image)
        return
    name = f"{save_dir}{b64_to_10(name.group(1))}.{name.group(2)}"
    if not overwrite and os.path.exists(name):
        logging.debug("Exists, continue: %s", name)
        return
    with urlopen(IMG_HOST + image.imageUrl) as r:
        data = r.read()
    key = bytes.fromhex(image.encryptionKey)
    iv = bytes.fromhex(image.iv)
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    out = decryptor.update(data) + decryptor.finalize()
    with open(name, "wb") as f:
        f.write(out)
    # os.system(f"curl -s \"{IMG_HOST}{image.imageUrl}\" | openssl aes-256-cbc -d -K {image.encryptionKey} -iv {image.iv} -in - -out {name}")
    logging.debug("Downloaded: %s", name)

def down_pages(
    save_dir: str,
    data, #: fuz_pb2.BookViewer2Response | fuz_pb2.MagazineViewer2Response | fuz_pb2.MangaViewerResponse,
    que: Queue
):
    os.makedirs(save_dir, exist_ok=True)
    with open(save_dir + "index.protobuf", "wb") as f:
        f.write(data.SerializeToString())
    with open(save_dir + "index.json", "w") as f:
        json.dump(json_format.MessageToDict(data), f, ensure_ascii=False, indent=4)
    if getattr(data, "bookIssue", False):
        downloadThumb(save_dir, data.bookIssue.thumbnailUrl)

    for page in data.pages:
        t = Thread(target=download, name=page.image.imageUrl, args=(save_dir, page.image))
        t.start()
        # download(save_dir, page)
        que.put(t)
    que.join()

def down_book(out_dir: str, book_id: int, token: str, que: Queue):
    book = get_book_index(book_id, token)
    bookIssueId = str(book.bookIssue.bookIssueId)
    logging.info("[%s]%s", bookIssueId, book.bookIssue.bookIssueName)
    down_pages(f"{out_dir}/b{bookIssueId}/", book, que)

def down_magazine(out_dir: str, magazine_id: int, token: str, que: Queue):
    magazine = get_magazine_index(magazine_id, token)
    magazineIssueId = str(magazine.MagazineIssue.magazineIssueId)
    logging.info("[%s]%s", magazineIssueId, magazine.MagazineIssue.magazineIssueName)
    down_pages(f"{out_dir}/z{magazineIssueId}/", magazine, que)

def down_manga(out_dir: str, manga_id: int, token: str, que: Queue):
    manga = get_manga_index(manga_id, token)
    logging.info("[%d]%s", manga_id, manga.viewerTitle)
    down_pages(f"{out_dir}/m{manga_id}/", manga, que)

def getParser():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-t',
        '--token-file',
        metavar='<Token文件路径>',
        help="Token文件路径（不指定此参数则不读入或保存Token）")
    parser.add_argument(
        '-u',
        '--user-email',
        metavar='<用户email>',
        help="用户email，不填且无Token的话会以游客身份登录")
    parser.add_argument(
        '-p',
        '--password',
        metavar='<密码>',
        nargs='?',
        help="密码可直接由命令行参数传入；不传入的话，如果指定了用户名（`-u`），将会询问")
    parser.add_argument(
        '-o',
        '--output-dir',
        metavar='<输出路径>',
        default=".",
        help="输出目录（默认当前目录）")
    parser.add_argument(
        '-j',
        '--n-jobs',
        metavar='<并行线程数>',
        type=int,
        default=16,
        help="并行线程数（默认16）")
    parser.add_argument(
        '-b',
        '--book',
        metavar='<BookId>',
        type=int,
        help="目标单行本Id")
    parser.add_argument(
        '-m',
        '--manga',
        metavar='<MangaId>',
        type=int,
        help="目标漫画Id")
    parser.add_argument(
        '-z',
        '--magazine',
        metavar='<MagazineId>',
        type=int,
        help="目标杂志Id")
    parser.add_argument(
        '-v',
        '--verbose',
        action="store_true",
        help="打印调试输出")
    return parser

def worker(que: Queue):
    count = 0
    while True:
        item = que.get()
        count += 1
        item.join()
        # logging.debug("[%d] ok.", count)
        que.task_done()

def main():
    parser = getParser()
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(message)s")
    logging.info("= ComicFuz-Extractor made with ♡ by EnkanRec =")
    os.makedirs(args.output_dir, exist_ok=True)

    token = get_session(args.token_file, args.user_email, args.password)
    que = Queue(args.n_jobs)
    Thread(target=worker, args=(que, ), daemon=True).start()

    if args.book:
        down_book(args.output_dir, args.book, token, que)
    if args.magazine:
        down_magazine(args.output_dir, args.magazine, token, que)
    if args.manga:
        down_manga(args.output_dir, args.manga, token, que)

    logging.debug("Done.")

main()