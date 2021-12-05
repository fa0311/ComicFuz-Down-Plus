# Get Ids
Get the manga/book/magazine id from url.
* `https://comic-fuz.com/manga/1902`
* `https://comic-fuz.com/book/25120`
* `https://comic-fuz.com/magazine/25812`

# Ssage
```
$ python fuz_down.py --help
usage: fuz_down.py [-h] [-t <Token文件路径>] [-u <用户email>] [-p [<密码>]] [-o <输出路径>] [-j <并行线程数>]
                   [-b <BookId>] [-m <MangaId>] [-z <MagazineId>] [-v]

optional arguments:
  -h, --help            show this help message and exit
  -t <Token文件路径>, --token-file <Token文件路径>
                        Token文件路径（不指定此参数则不读入或保存Token）
  -u <用户email>, --user-email <用户email>
                        用户email，不填且无Token的话会以游客身份登录
  -p [<密码>], --password [<密码>]
                        密码可直接由命令行参数传入；不传入的话，如果指定了用户名（`-u`），将会询问
  -o <输出路径>, --output-dir <输出路径>
                        输出目录（默认当前目录）
  -j <并行线程数>, --n-jobs <并行线程数>
                        并行线程数（默认16）
  -b <BookId>, --book <BookId>
                        目标单行本Id
  -m <MangaId>, --manga <MangaId>
                        目标漫画Id
  -z <MagazineId>, --magazine <MagazineId>
                        目标杂志Id
  -v, --verbose         打印调试输出
```

# More

[Official protobuf in js](https://comic-fuz.com/_next/static/chunks/pages/_app-b24da103ab4a3f25b6bc.js)

[tampermonkey script by CircleLiu](https://github.com/CircleLiu/Comic-Fuz-Downloader)
