#!/usr/bin/env python3
"""
TANKI ONLINE — авторитарный игровой сервер (только stdlib, чистый asyncio).

Запуск:            python3 server.py        ->  http://0.0.0.0:8080
Переменные окружения (перекрывают config.json):
  PORT              порт HTTP/WS               (по умолчанию 8080)
  HOST              адрес привязки             (0.0.0.0)
  ADMIN_KEY         ключ админ-API /api/admin/* и WS {"t":"admin"} (пусто = API закрыт)
  TRUST_PROXY       1 = доверять X-Forwarded-For (за reverse-proxy, напр. Koyeb).
                    Берётся ПОСЛЕДНИЙ IP списка — прокси дописывает реальный IP
                    клиента в конец, первый элемент клиент может подделать.
  STATIC_DIR        папка статики              (.)
  DATA_DIR          папка данных               (data)
  MAX_CONN_PER_IP   лимит одновременных WS     (8)
  ALLOWED_ORIGINS   список Origin через запятую (пусто = любые)
  AUTH_PER_MIN      попыток входа в минуту с одного IP (10)
  AUTH_GLOBAL_PER_MIN  попыток входа в минуту на весь сервер (120)
  RESTART_HOURS     плановый перезапуск процесса каждые N часов (6; 0 = выключен).
                    За 10/5/2/1 мин, 30/10/5 сек игрокам приходит предупреждение,
                    затем данные сохраняются и процесс перезапускается через os.execv
                    (контейнер остаётся тем же, data/ не теряется). Клиенты переподключаются сами.

data/ (атомарная запись tmp + os.replace):
  accounts.json   аккаунты: id, login, name, salt/hash (PBKDF2-SHA256), stats, lo, crystals
  sessions.json   токены -> {aid, exp} (скользящее продление, session_days)
  bans.json       {'ip': {...}, 'acc': {...}}; until=0 — навсегда

HTTP API:
  POST /api/register {login,password,name} -> {ok,token,id,name,lo,stats,up_pts}
  POST /api/login    {login,password}      -> аналогично
  GET  /api/rooms                          -> [{id,n,b,r,cap,map,tl,st,team,pl}]
  GET  /health                             -> 'ok'
  GET  /admin.html                         -> админ-панель (ключ в localStorage)
  /api/admin/*  заголовок X-Admin-Key:
      GET  state     -> uptime, conns, rooms, players(ip!), accounts, bans
      POST kick      {id}              — выкинуть игрока
      POST broadcast {text}            — сообщение всем как 'АДМИН'
      POST ban       {ip|aid, hours(0=навсегда), reason}
      POST unban     {ip|aid}
      POST delacc    {aid}             — удалить аккаунт (+сессии)
      POST save                        — сохранить data/ немедленно
      POST restart   {delay, cancel}   — перезапуск через delay сек (по умолч. 30); cancel=true — вернуть плановый срок

WS (JSON, поле "t"): клиент -> сервер
  auth    {token} | {login,password}   регистронезависимо, одна сессия на аккаунт
  hello / rooms                            список комнат
  join    {room, team}                    вход в комнату (лоадаут — строго из аккаунта)
  leave                                    выход из комнаты
  st      {x,z,r,a,v}                     позиция (валидация скорости, страйки -> бан)
  shot    {s:[[ox,oz,dx,dz,dy,spread]]}   выстрел (кулдаун/количество валидируются)
  hit     {v, d, g}                        попадание (урон клампится к max_damage())
  item    {k}  mine {x,z}  gold  od        припасы/мина/золотой ящик/овердрайв
  spot    {id,x,z}                         ответ лидера на need_spot
  pick    {id}  pass {dx,dz}  chat {m,c}   подбор/пас/чат ('all'|'team')
  admin   {key, cmd}                       админ-команды по WS
сервер -> клиент: welcome, rooms, joined, pl_join, pl_leave, snap, need_spot,
  shot, hp, dead, respawn, ev{flag_take/drop/ret/cap, mine_*, pk_*, bx_*,
  ball_*, jugg_*, tickets, siege_*}, end, chat, kicked, auth_ok, auth_err, fix

Комнаты: DM, TDM, CTF, CP, SIEGE, ASLT, RGB, JUGG. Тик 20 Гц, снапшоты 10 Гц.
Устойчивость: room.tick при повторных сбоях (>=50) мягко перезапускает матч.
Graceful shutdown по SIGTERM/SIGINT: сохранение data/ и закрытие всех WS.
"""
import asyncio
import base64
import concurrent.futures
import copy
import gzip
import hashlib
import hmac
import json
import logging
import math
import mimetypes
import os
import random
import re
import secrets
import shutil
import signal
import struct
import sys
import time
from pathlib import Path
from urllib.parse import unquote

BASE = Path(__file__).resolve().parent
GUID = b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
log = logging.getLogger('tanki')
START_T = time.time()
START_MONO = time.monotonic()

# ------------------------------------------------------------------ конфиг
CFG = {
    'host': '0.0.0.0',
    'port': 8080,
    'room_capacity': 16,
    'match_end_delay': 12,
    'max_msg_per_sec': 90,
    'max_conn_per_ip': 8,
    'allowed_origins': [],
    'static_dir': 'static',
    'data_dir': 'data',
    'auth_required': True,
    'session_days': 7,
    'pbkdf2_iters': 200000,
    'auth_per_min': 10,
    'auth_global_per_min': 120,
    'admin_key': '',          # ВСЕГДА берётся только из переменной окружения ADMIN_KEY
    'trust_proxy': False,
    'restart_hours': 6,       # плановый перезапуск, часы (0 = выключен)
}


def load_cfg():
    p = BASE / 'config.json'
    if p.exists():
        try:
            CFG.update(json.loads(p.read_text(encoding='utf-8')))
        except Exception as e:  # noqa
            log.warning('config.json: %s', e)
    env_map = {
        'PORT': ('port', int), 'HOST': ('host', str),
        'MAX_CONN_PER_IP': ('max_conn_per_ip', int),
        'STATIC_DIR': ('static_dir', str), 'DATA_DIR': ('data_dir', str),
        'AUTH_PER_MIN': ('auth_per_min', int),
        'AUTH_GLOBAL_PER_MIN': ('auth_global_per_min', int),
        'RESTART_HOURS': ('restart_hours', float),
    }
    if CFG.get('admin_key'):
        log.warning('config.json: admin_key игнорируется — используйте переменную окружения ADMIN_KEY')
    CFG['admin_key'] = os.environ.get('ADMIN_KEY', '').strip()
    for env, (key, cast) in env_map.items():
        if os.environ.get(env):
            try:
                CFG[key] = cast(os.environ[env])
            except ValueError:
                log.warning('bad env %s=%r', env, os.environ[env])
    if os.environ.get('ALLOWED_ORIGINS'):
        CFG['allowed_origins'] = [o.strip() for o in os.environ['ALLOWED_ORIGINS'].split(',') if o.strip()]
    if os.environ.get('TRUST_PROXY') in ('1', 'true', 'yes'):
        CFG['trust_proxy'] = True


# ------------------------------------------------------------------ данные игры (из клиента)
CLASSES = {
    'light': dict(hp=80, speed=16.5, dmg=0.9, reload=0.88, armor=0.9),
    'medium': dict(hp=110, speed=13.0, dmg=1.0, reload=1.0, armor=1.0),
    'heavy': dict(hp=175, speed=9.4, dmg=1.24, reload=1.2, armor=1.28),
}
GUNS = {
    'smoky': dict(damage=26, cooldown=950, count=1, splash=0, pierce=0, slow=0, speed=100),
    'thunder': dict(damage=46, cooldown=1650, count=1, splash=6, pierce=0, slow=0, speed=84),
    'twins': dict(damage=15, cooldown=640, count=2, splash=0, pierce=0, slow=0, speed=116),
    'freeze': dict(damage=13, cooldown=1050, count=1, splash=0, pierce=0, slow=3, speed=74),
    'railgun': dict(damage=92, cooldown=3200, count=1, splash=0, pierce=2, slow=0, speed=200),
}
ITEM_CD = {'repair': 10, 'armor': 22, 'damage': 22, 'speed': 22, 'mine': 30, 'gold': 30}
JUGG = dict(hp=1500, dmg=2.0, speed=0.85, reload=0.7, respawn=3.0)
MODES = {
    'DM': dict(name='Deathmatch', team=False, time=300, target=12),
    'TDM': dict(name='Командный бой', team=True, time=420, target=600),
    'CTF': dict(name='Захват флага', team=True, time=420, target=5),
    'CP': dict(name='Контроль точек', team=True, time=420, target=600),
    'SIEGE': dict(name='Осада', team=True, time=480, target=1000),
    'ASLT': dict(name='Штурм', team=True, time=600, target=3),
    'RGB': dict(name='Регби', team=True, time=420, target=5),
    'JUGG': dict(name='Командный джаггернаут', team=True, time=480, target=10),
}
MAPS = {
    'city': dict(blueFlag=(0, 158), redFlag=(0, -158), blueBase=(-150, 0), redBase=(150, 0),
                 points=[(-100, 70), (0, -105), (100, 70)], zones=[(-55, -60), (0, 60), (55, -60)]),
    'village': dict(blueFlag=(-138, 96), redFlag=(138, -96), blueBase=(-165, 0), redBase=(165, 0),
                    points=[(-88, 22), (0, 0), (88, -22)], zones=[(-45, -55), (0, 45), (45, -55)]),
    'fort': dict(blueFlag=(-140, -30), redFlag=(140, 30), blueBase=(-165, 0), redBase=(165, 0),
                 points=[(-96, -92), (0, 0), (80, 80)], zones=[(0, -70), (-55, 42), (55, 42)]),
}
MAP_ORDER = ['city', 'village', 'fort']
PICKUPS = ['repair', 'armor', 'damage', 'speed', 'crystal']
RESPAWN_S = 4.2
GHOST_S = 2.6
TICK = 0.05            # 20 Гц
SNAP_EVERY = 2         # снапшоты 10 Гц
WS_PING_INTERVAL = 25.0
WS_READ_TIMEOUT = 90.0
SAVE_INTERVAL = 30.0
# --- античит (подстроить под реальную физику клиента при ложных срабатываниях)
SHOT_ORIGIN_MAX = 8.0      # макс. расстояние точки выстрела от позиции танка (дуло railgun у heavy ~6)
HIT_MAX_DIST = 320.0       # жёсткий потолок дальности попадания
HIT_RANGE_K = 2.4          # дальность попадания = speed*K + 20 (ограничена HIT_MAX_DIST)
HIT_FLIGHT_SLACK = 1.2     # попадание допустимо не позже dist/speed + slack после выстрела
HULL_TURN_MAX = 8.0        # рад/с, поворот корпуса
TURRET_TURN_MAX = 14.0     # рад/с, поворот башни
ANGLE_SLACK = 0.35         # рад, запас на jitter пакетов
ROOM_CHANGE_CD = 2.5       # сек между входами/выходами из комнат
SPOT_LIMIT = 200.0         # спавн предметов только в квадрате |x|,|z| <= SPOT_LIMIT
SPOT_CLEAR = 8.0           # и не ближе к флагам/базам/точкам

# ------------------------------------------------------------------ модерация: банворды/правила/варны
# Действия банвордов по возрастанию строгости:
#   censor — слово маскируется «***», сообщение уходит
#   block  — сообщение не доходит, игроку предупреждение
#   mute   — как block + автоматический мут чата
#   ban    — как block + автоматический бан аккаунта и IP
MOD_ACTIONS = ('censor', 'block', 'mute', 'ban')

# ЗАКРЕПЛЁННЫЕ слова (pin=True): их нельзя удалить через админ-панель — только добавить свои.
# Список — стартовый: судьи не нужны, за наркоту/преступления здесь бан.
DEFAULT_BANWORDS = [
    # наркотики и запрещённые вещества (заодно «продам/куплю»-комбинации ловит «нарко»)
    ('наркотик', 'ban'), ('наркота', 'ban'), ('наркоты', 'ban'), ('нарко', 'ban'),
    ('мефедрон', 'ban'), ('меф', 'ban'), ('амфетамин', 'ban'), ('кокаин', 'ban'),
    ('героин', 'ban'), ('гашиш', 'ban'), ('марихуана', 'ban'), ('каннабис', 'ban'),
    ('анаша', 'ban'), ('экстази', 'ban'), ('спайс', 'ban'), ('мдма', 'ban'),
    ('лсд', 'ban'), ('опиум', 'ban'), ('метадон', 'ban'), ('мефедрон', 'ban'),
    ('продам нарко', 'ban'), ('куплю нарко', 'ban'), ('достану нарко', 'ban'),
    # терроризм и реальные преступления
    ('теракт', 'ban'), ('террорист', 'ban'), ('терорист', 'ban'), ('взрывчатк', 'ban'),
    ('закажу убийств', 'ban'), ('заказать убийств', 'ban'), ('наёмный убийц', 'ban'),
    ('наемный убийц', 'ban'),
    # недопустимый контент
    ('детское порно', 'ban'), ('детск порн', 'ban'), ('порно дети', 'ban'),
    ('инцест', 'ban'),
    # продажа аккаунтов и мошенничество
    ('продам аккаунт', 'mute'), ('продам акк', 'mute'), ('куплю аккаунт', 'mute'),
    ('куплю акк', 'mute'), ('продажа аккаунтов', 'mute'), ('скинь пароль', 'mute'),
    ('дай пароль', 'mute'), ('введи пароль от', 'mute'),
    # оскорбления и мат
    ('хуй', 'block'), ('хуе', 'block'), ('хуё', 'block'), ('нахуй', 'block'),
    ('похуй', 'block'), ('похую', 'block'), ('пизд', 'block'), ('еба', 'block'),
    ('ёба', 'block'), ('ебан', 'block'), ('ёбан', 'block'), ('ебат', 'block'),
    ('ебуч', 'block'), ('бля', 'block'), ('сука', 'block'), ('мудак', 'block'),
    ('мудило', 'block'), ('гандон', 'block'), ('гондон', 'block'), ('чмо', 'block'),
    ('долбоёб', 'block'), ('долбоеб', 'block'), ('гнида', 'block'), ('дебил', 'block'),
    ('сдохни', 'block'), ('иди в жопу', 'block'),
    # формы слов-корней (длина >= 5, чтобы ловились как подстрока в сплошном тексте)
    ('ебать', 'block'), ('ебал', 'block'), ('ебуч', 'block'), ('ебешь', 'block'),
    ('пизда', 'block'), ('пиздец', 'block'), ('пизды', 'block'), ('пиздит', 'block'),
    ('пиздюк', 'block'), ('пизде', 'block'),
    ('нахуй', 'block'), ('похуй', 'block'), ('хуесос', 'block'), ('хуило', 'block'),
    ('блядь', 'block'), ('бляди', 'block'), ('блядс', 'block'), ('сукин', 'block'),
    ('сучка', 'block'), ('сучара', 'block'), ('хуйня', 'block'), ('хуйло', 'block'),
    # обход фильтра транслитом
    ('xyu', 'block'), ('pizd', 'block'), ('eban', 'block'), ('blya', 'block'),
    ('narkotik', 'ban'), ('narkota', 'ban'), ('suka', 'block'),
    ('ebat', 'block'), ('pizda', 'block'), ('blyad', 'block'), ('huilo', 'block'),
]

# Правила сервера (видны игрокам в лобби — кнопка «ПРАВИЛА», редактируются в админ-панели).
DEFAULT_RULES = [
    {'text': 'Запрещены продажа, покупка, реклама и любое упоминание наркотиков, '
             'запрещённых веществ и «солей». Наказание: бан навсегда, IP — тоже.', 'p': 'БАН НАВСЕГДА'},
    {'text': 'Запрещены угрозы реальной расправой, призывы к насилию, терроризму и '
             'любые противозаконные действия. Наказание: бан навсегда.', 'p': 'БАН НАВСЕГДА'},
    {'text': 'Запрещено распространение личных данных игроков (адреса, телефоны, документы) '
             'и шантаж. Наказание: бан навсегда.', 'p': 'БАН НАВСЕГДА'},
    {'text': 'Запрещены мошенничество, продажа/покупка аккаунтов и попытки украсть '
             'чужой аккаунт. Наказание: бан от 24 часов до навсегда.', 'p': 'БАН 24Ч — НАВСЕГДА'},
    {'text': 'Запрещены читы, макросы, багоюз и любое вмешательство в работу сервера. '
             'Наказание: бан навсегда без предупреждений.', 'p': 'БАН НАВСЕГДА'},
    {'text': 'Запрещены оскорбления, мат, травля и разжигание конфликтов. Наказание: '
             'предупреждение → мут → бан.', 'p': 'ВАРН → МУТ → БАН'},
    {'text': 'Запрещён спам и флуд в чате (повторяющиеся сообщения, капс, мусор). '
             'Наказание: мут от 30 минут.', 'p': 'МУТ 30 МИН'},
    {'text': 'Запрещена реклама сторонних серверов, сайтов и сервисов без разрешения '
             'администрации. Наказание: мут → бан.', 'p': 'МУТ → БАН'},
    {'text': 'Обход бана новым аккаунтом продлевает бан IP-адреса. Наказание: бан IP.', 'p': 'БАН IP'},
    {'text': 'Запрещено мешать игре: тимкилл, затяжные бои саботажем, уход от боя АФК. '
             'Наказание: кик → бан.', 'p': 'КИК → БАН'},
    {'text': 'Запрещено выдавать себя за администрацию и игроков других серверов. '
             'Наказание: бан 24 часа.', 'p': 'БАН 24Ч'},
    {'text': 'Незнание правил не освобождает от наказания. Администрация вправе выдать '
             'наказание за действия, не описанные здесь, но нарушающие законы или '
             'нормальное общение.', 'p': 'НА УСМОТРЕНИЕ АДМИНА'},
]

MODSET_DEF = {
    'enabled': True,        # авто-модерация чата включена
    'name_check': True,     # проверка ника на банворды при регистрации
    'mute_at': 3,           # столько предупреждений → автоматический мут
    'ban_at': 5,            # столько предупреждений → автоматический бан
    'permaban_at': 8,       # столько предупреждений → вечный бан (0 = выключено)
    'mute_minutes': 30,     # срок автомута
    'ban_hours': 24,        # срок автобана по варнам (0 = навсегда)
    'auto_ban_hours': 24,   # срок автобана за слова категории ban (0 = навсегда)
    'warn_decay_h': 48,     # предупреждение сгорает через столько часов
    'flood_msgs': 8,        # антифлуд: больше сообщений за окно → мут
    'flood_window_s': 10,   # окно антифлуда, секунд
    'flood_mute_min': 5,    # срок мута за флуд (0 = только предупреждение)
}
CHATLOG_MAX = 500          # размер журнала чата в памяти
MODLOG_MAX = 400           # размер журнала модерации в памяти

# ------------------------------------------------------------------ защита админ-API от перебора ключа
ADMIN_FAIL_WINDOW = 300.0    # окно учёта неудачных попыток, сек
ADMIN_FAIL_MAX = 5           # столько неудач за окно → блокировка админ-API для IP
ADMIN_BLOCK_SECONDS = 600.0  # срок блокировки после перебора
_ADMIN_FAILS = {}            # ip -> [время последнего освобождения, список неудач]


def _admin_fails(ip):
    rec = _ADMIN_FAILS.setdefault(ip, [0.0, []])
    t = time.time()
    # если IP уже отбывал блокировку и она истекла — обнуляем счётчик
    if rec[0] and t - rec[0] >= ADMIN_BLOCK_SECONDS:
        rec[0], rec[1] = 0.0, []
    while rec[1] and t - rec[1][0] > ADMIN_FAIL_WINDOW:
        rec[1].pop(0)
    return rec


def admin_blocked(ip):
    """IP заблокирован за перебор админ-ключа."""
    rec = _ADMIN_FAILS.get(ip)
    if not rec:
        return False
    t = time.time()
    if rec[0] and t - rec[0] < ADMIN_BLOCK_SECONDS:
        return True
    if rec[0]:
        rec[0], rec[1] = 0.0, []
    return False


def admin_fail(ip):
    """Неудачная попытка входа в админ-API; True = теперь IP заблокирован."""
    rec = _admin_fails(ip)
    rec[1].append(time.time())
    if len(rec[1]) > ADMIN_FAIL_MAX:
        rec[0] = time.time()
        rec[1] = []
        log.warning('admin: перебор ключа с %s — блокировка на %d сек', ip, int(ADMIN_BLOCK_SECONDS))
        return True
    return False


def admin_ok_ip(ip):
    """Успешная попытка — сброс счётчика неудач."""
    _ADMIN_FAILS.pop(ip, None)


def now():
    return time.monotonic()


def clamp(v, a, b):
    return a if v < a else (b if v > b else v)


def d2(ax, az, bx, bz):
    return math.hypot(ax - bx, az - bz)


def clean_name(n):
    s = re.sub(r'[<>&"\'`\\\x00-\x1f]', '', str(n or ''))
    s = re.sub(r'\s+', ' ', s).strip()[:16]
    return s or 'Игрок'


def clean_login(s):
    return re.sub(r'[^A-Za-z0-9_]', '', str(s or ''))[:16]


def valid_login(s):
    return bool(re.fullmatch(r'[A-Za-z0-9_]{3,16}', s or ''))


def num(v, default=0.0):
    try:
        f = float(v)
        return f if math.isfinite(f) else default
    except (TypeError, ValueError):
        return default


_BG_TASKS = set()


def spawn(coro):
    """create_task с удержанием ссылки: иначе задача может быть собрана GC до завершения
    (статистика/бан «пропадали»), а исключения уходили в пустоту."""
    task = asyncio.create_task(coro)
    _BG_TASKS.add(task)

    def _done(t):
        _BG_TASKS.discard(t)
        if not t.cancelled() and t.exception() is not None:
            log.error('background task failed: %r', t.exception())
    task.add_done_callback(_done)
    return task


# ------------------------------------------------------------------ WebSocket (stdlib)
MAX_FRAME = 16 * 1024


def make_frame(text: str, opcode=0x1) -> bytes:
    data = text.encode('utf-8')
    n = len(data)
    if n < 126:
        head = struct.pack('!BB', 0x80 | opcode, n)
    elif n < 65536:
        head = struct.pack('!BBH', 0x80 | opcode, 126, n)
    else:
        head = struct.pack('!BBQ', 0x80 | opcode, 127, n)
    return head + data


async def read_frame(reader):
    b1, b2 = await reader.readexactly(2)
    opcode = b1 & 0x0F
    fin = bool(b1 & 0x80)
    masked = bool(b2 & 0x80)
    if b1 & 0x70:
        raise ValueError('reserved bits set')
    if not masked:
        raise ValueError('unmasked client frame')
    if opcode == 0x0:
        raise ValueError('continuation frame without start (fragmentation not allowed)')
    if opcode in (0x3, 0x4, 0x5, 0x6, 0x7) or opcode > 0xA:
        raise ValueError('bad opcode')
    if opcode in (0x1, 0x2) and not fin:
        raise ValueError('fragmented data frame rejected')
    if opcode >= 0x8 and (not fin or (b2 & 0x7F) > 125):
        raise ValueError('bad control frame')
    ln = b2 & 0x7F
    if ln == 126:
        ln = struct.unpack('!H', await reader.readexactly(2))[0]
    elif ln == 127:
        ln = struct.unpack('!Q', await reader.readexactly(8))[0]
    if ln > MAX_FRAME:
        raise ValueError('frame too large')
    mask = await reader.readexactly(4)
    data = await reader.readexactly(ln) if ln else b''
    if ln:
        m = (mask * (ln // 4 + 1))[:ln]
        data = (int.from_bytes(data, 'big') ^ int.from_bytes(m, 'big')).to_bytes(ln, 'big')
    return fin, opcode, data


class Conn:
    def __init__(self, reader, writer, ip):
        self.reader, self.writer, self.ip = reader, writer, ip
        self.closed = False
        self.player = None
        self.win_t = now()
        self.win_n = 0

    def send_frame(self, frame: bytes):
        if self.closed:
            return
        try:
            tr = self.writer.transport
            if tr is None or tr.is_closing():
                self.closed = True
                return
            if tr.get_write_buffer_size() > 1_500_000:  # медленный клиент
                self.close()
                return
            self.writer.write(frame)
        except Exception:
            self.closed = True

    def send(self, obj):
        self.send_frame(make_frame(json.dumps(obj, separators=(',', ':'), ensure_ascii=False)))

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            self.writer.write(struct.pack('!BB', 0x88, 0))
            self.writer.close()
        except Exception:
            pass


# ------------------------------------------------------------------ хранилище аккаунтов/сессий/банов
class Store:
    DEF_LO = {'cls': 'medium', 'gun': 'smoky', 'pt': 0,
              'up': {'engine': 0, 'armor': 0, 'gun': 0, 'reload': 0}}

    def __init__(self, data_dir):
        self.dir = Path(data_dir)
        self.lock = asyncio.Lock()
        self.accounts = {}   # login_lower -> acc
        self.by_id = {}      # id -> acc
        self.sessions = {}   # token -> {'aid': int, 'exp': float}
        self.bans = {'ip': {}, 'acc': {}}
        self.news = []       # новости сервера для ленты «Новости» в клиенте
        self.banwords = []   # [{'w','a','pin'}] запрещённые слова (pin — закреплённые)
        self.rules = []      # [{'text','p'}] правила сервера (кнопка «ПРАВИЛА» в лобби)
        self.modset = dict(MODSET_DEF)   # настройки авто-модерации
        self.chatlog = []    # журнал чата (кольцевой буфер)
        self.modlog = []     # журнал модерации/админ-действий
        self.seq = 0
        self.dirty = False

    def _backup_snapshots(self):
        """Раз в запуск: снимок последних хороших accounts.json/moderation.json
        в data/backups/ (хранятся последние 5). Спасает данные при сбойной записи."""
        try:
            bdir = self.dir / 'backups'
            bdir.mkdir(parents=True, exist_ok=True)
            stamp = time.strftime('%Y%m%d-%H%M%S')
            for name in ('accounts.json', 'moderation.json', 'bans.json'):
                f = self.dir / name
                if f.is_file():
                    shutil.copy2(f, bdir / ('%s.%s.bak' % (name, stamp)))
            for prefix in ('accounts.json', 'moderation.json', 'bans.json'):
                olds = sorted(bdir.glob('%s.*.bak' % prefix))
                for old in olds[:-5]:
                    try:
                        old.unlink()
                    except OSError:
                        pass
        except Exception as e:  # noqa
            log.warning('backup: %s', e)

    async def load(self):
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            probe = self.dir / '.write_probe'
            probe.write_text('ok', encoding='utf-8')
            probe.unlink()
        except Exception as e:  # noqa
            log.error('data-каталог %s недоступен для записи (%s) — '
                      'проверьте volume/права; сервер работает БЕЗ сохранения данных', self.dir, e)
        self._backup_snapshots()
        async with self.lock:
            try:
                f = self.dir / 'accounts.json'
                if f.exists():
                    raw = json.loads(f.read_text(encoding='utf-8'))
                    self.seq = int(raw.get('seq', 0))
                    for acc in raw.get('accounts', []):
                        self.accounts[acc['login'].lower()] = acc
                        self.by_id[acc['id']] = acc
                        self._repair_acc(acc)
                    # ремонт seq: если файл повреждён/писался старой версией,
                    # новые id не должны пересекаться с существующими (иначе угон аккаунта)
                    self.seq = max([self.seq] + [a['id'] for a in self.accounts.values()] + [0])
            except Exception as e:  # noqa
                log.warning('accounts load: %s', e)
            try:
                f = self.dir / 'sessions.json'
                if f.exists():
                    t = time.time()
                    self.sessions = {k: v for k, v in json.loads(f.read_text(encoding='utf-8')).items()
                                     if v.get('exp', 0) > t}
            except Exception as e:  # noqa
                log.warning('sessions load: %s', e)
            try:
                f = self.dir / 'bans.json'
                if f.exists():
                    self.bans = json.loads(f.read_text(encoding='utf-8'))
                    self.bans.setdefault('ip', {})
                    self.bans.setdefault('acc', {})
            except Exception as e:  # noqa
                log.warning('bans load: %s', e)
            try:
                f = self.dir / 'news.json'
                if f.exists():
                    news = json.loads(f.read_text(encoding='utf-8'))
                    self.news = news if isinstance(news, list) else []
            except Exception as e:  # noqa
                log.warning('news load: %s', e)
            try:
                f = self.dir / 'moderation.json'
                if f.exists():
                    m = json.loads(f.read_text(encoding='utf-8'))
                    if isinstance(m.get('banwords'), list):
                        self.banwords = [bw for bw in m['banwords']
                                         if isinstance(bw, dict) and isinstance(bw.get('w'), str)
                                         and bw.get('a') in MOD_ACTIONS]
                    if isinstance(m.get('rules'), list):
                        self.rules = [r for r in m['rules']
                                      if isinstance(r, dict) and isinstance(r.get('text'), str)]
                    if isinstance(m.get('modset'), dict):
                        for k in MODSET_DEF:
                            if k in m['modset']:
                                try:
                                    self.modset[k] = type(MODSET_DEF[k])(m['modset'][k])
                                except (TypeError, ValueError):
                                    pass
                    if isinstance(m.get('chatlog'), list):
                        self.chatlog = [c for c in m['chatlog'] if isinstance(c, dict)][-CHATLOG_MAX:]
                    if isinstance(m.get('modlog'), list):
                        self.modlog = [c for c in m['modlog'] if isinstance(c, dict)][-MODLOG_MAX:]
            except Exception as e:  # noqa
                log.warning('moderation load: %s', e)
            # первый запуск: сеем закреплённые слова и правила
            if not self.banwords:
                self.banwords = [{'w': w, 'a': a, 'pin': True} for w, a in DEFAULT_BANWORDS]
                self.dirty = True
            else:
                # после обновления сервера досеиваем НОВЫЕ закреплённые слова:
                # у старых установок список не перезатирается, но дефолты дополняются
                have = {w['w'].lower() for w in self.banwords}
                added = False
                for w, a in DEFAULT_BANWORDS:
                    if w.lower() not in have:
                        self.banwords.append({'w': w, 'a': a, 'pin': True})
                        added = True
                if added:
                    self.dirty = True
                    log.info('moderation: досеяны новые закреплённые банворды')
            if not self.rules:
                self.rules = [dict(r) for r in DEFAULT_RULES]
                self.dirty = True

    @staticmethod
    def _repair_acc(acc):
        """Аккаунт из старой версии data/ может не иметь новых полей — без этого
        on_auth падал с KeyError и игрок не мог войти под старым аккаунтом."""
        acc.setdefault('name', acc.get('login', 'Игрок'))
        acc.setdefault('banned', None)
        acc.setdefault('crystals', 0)
        acc.setdefault('warns', [])
        acc.setdefault('stats', {'games': 0, 'wins': 0, 'kills': 0, 'deaths': 0, 'score': 0})
        acc.setdefault('lo', {'cls': 'medium', 'gun': 'smoky', 'pt': 0,
                              'up': {'engine': 0, 'armor': 0, 'gun': 0, 'reload': 0}})
        for k in ('games', 'wins', 'kills', 'deaths', 'score'):
            acc['stats'][k] = int(num(acc['stats'].get(k), 0))

    def _write(self, name, obj):
        tmp = self.dir / (name + '.tmp')
        tmp.write_text(json.dumps(obj, ensure_ascii=False), encoding='utf-8')
        os.replace(tmp, self.dir / name)

    def _write_all(self, snap):
        self._write('accounts.json', snap['accounts'])
        self._write('sessions.json', snap['sessions'])
        self._write('bans.json', snap['bans'])
        self._write('news.json', snap['news'])
        self._write('moderation.json', snap['moderation'])

    @staticmethod
    def _mod_words():
        # в файл идут только сами слова, без кэшей компиляции
        return [{'w': w['w'], 'a': w.get('a', 'block'), 'pin': bool(w.get('pin'))}
                for w in STORE.banwords]

    @staticmethod
    def _mod_snap():
        return {'banwords': Store._mod_words(), 'rules': copy.deepcopy(STORE.rules),
                'modset': dict(STORE.modset),
                'chatlog': STORE.chatlog[-200:], 'modlog': STORE.modlog[-200:]}

    async def save(self, force=False):
        async with self.lock:
            if not force and not self.dirty:
                return
            t = time.time()
            self.sessions = {k: v for k, v in list(self.sessions.items()) if v['exp'] > t}
            # глубокие копии: сериализация идёт в потоке, пока игровой цикл меняет данные
            snap = copy.deepcopy({
                'accounts': {'seq': self.seq, 'accounts': list(self.accounts.values())},
                'sessions': self.sessions,
                'bans': self.bans,
                'news': self.news,
                'moderation': self._mod_snap(),
            })
            self.dirty = False
            try:
                await asyncio.get_running_loop().run_in_executor(None, self._write_all, snap)
            except Exception:
                self.dirty = True
                raise

    # ---- крипто
    # PBKDF2 (200k итераций ~ 50-100 мс CPU) выполняется в потоке-исполнителе,
    # чтобы брутфорс логинов не подвешивал игровой цикл.
    HASH_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix='pbkdf2')
    # фиктивная пара salt/hash — проверяется, когда логина нет (защита от
    # тайминг-перебора существующих логинов)
    _DUMMY_SALT = ('0123456789abcdef0123456789abcdef')
    _DUMMY_HASH = ('0' * 64)

    @classmethod
    async def _hash_async(cls, password, salt=None, iters=None):
        loop = asyncio.get_running_loop()
        salt = salt or os.urandom(16)
        iters = iters or CFG['pbkdf2_iters']
        return await loop.run_in_executor(
            cls.HASH_POOL, cls._hash_sync, password, salt, iters)

    @staticmethod
    def _hash_sync(password, salt, iters):
        dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iters)
        return salt.hex(), dk.hex(), iters

    @staticmethod
    def _verify(password, salt_hex, hash_hex, iters):
        dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes.fromhex(salt_hex), iters)
        return hmac.compare_digest(dk.hex(), hash_hex)

    @classmethod
    async def _verify_async(cls, password, salt_hex, hash_hex, iters):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            cls.HASH_POOL, cls._verify, password, salt_hex, hash_hex, iters)

    async def _dummy_verify(self, password):
        # съедает столько же времени, сколько настоящая проверка — тайминги равны
        await self._verify_async(password, self._DUMMY_SALT, self._DUMMY_HASH, CFG['pbkdf2_iters'])

    def _new_session(self, aid):
        token = secrets.token_urlsafe(32)
        self.sessions[token] = {'aid': aid, 'exp': time.time() + CFG['session_days'] * 86400}
        self.dirty = True
        return token

    def auth_token(self, token):
        s = self.sessions.get(token)
        if not s:
            return None, None
        if s['exp'] < time.time():
            self.sessions.pop(token, None)
            self.dirty = True
            return None, None
        acc = self.by_id.get(s['aid'])
        if not acc:
            return None, None
        s['exp'] = time.time() + CFG['session_days'] * 86400  # скользящее продление
        self.dirty = True
        return acc, token

    async def register(self, login, password, name=None):
        login = clean_login(login)
        if not valid_login(login):
            return False, 'Логин: 3-16 символов (A-Z, a-z, 0-9, _)', None
        if not isinstance(password, str) or not (6 <= len(password) <= 64):
            return False, 'Пароль: 6-64 символа', None
        # хэш считаем ДО блокировки — не тормозим остальных
        salt, hash_hex, iters = await self._hash_async(password)
        name = clean_name(name) if name else login
        if self.modset.get('name_check', True) and not name_allowed(name):
            return False, 'Ник содержит запрещённые слова. Выберите другой.', None
        if self.modset.get('name_check', True) and not name_allowed(login):
            return False, 'Логин содержит запрещённые слова. Выберите другой.', None
        async with self.lock:
            if login.lower() in self.accounts:
                return False, 'Такой логин уже занят', None
            self.seq += 1
            acc = {
                'id': self.seq, 'login': login,
                'name': name,
                'salt': salt, 'hash': hash_hex, 'iters': iters,
                'created': time.time(), 'last_login': time.time(), 'banned': None,
                'warns': [],
                'stats': {'games': 0, 'wins': 0, 'kills': 0, 'deaths': 0, 'score': 0},
                'lo': {'cls': 'medium', 'gun': 'smoky', 'pt': 0,
                       'up': {'engine': 0, 'armor': 0, 'gun': 0, 'reload': 0}},
            }
            self.accounts[login.lower()] = acc
            self.by_id[acc['id']] = acc
            token = self._new_session(acc['id'])
            self.dirty = True
            return True, '', token

    async def login_user(self, login, password):
        """Вход: PBKDF2 в executor, для чужого логина — фиктивная проверка
        (одинаковый тайминг ответа, перебор логинов по скорости невозможен)."""
        password = str(password or '')
        acc = self.accounts.get(clean_login(login).lower())
        if not acc:
            await self._dummy_verify(password)
            return False, 'Неверный логин или пароль', None
        iters = acc.get('iters', CFG['pbkdf2_iters'])
        if not await self._verify_async(password, acc['salt'], acc['hash'], iters):
            return False, 'Неверный логин или пароль', None
        if self.acc_banned(acc):
            return False, 'Аккаунт заблокирован', None
        acc['last_login'] = time.time()
        token = self._new_session(acc['id'])
        self.dirty = True
        return True, '', token

    # ---- лоадаут и прокачка (серверные!)
    @staticmethod
    def upgrade_points(acc):
        st = acc.get('stats') or {}
        return min(20, 2 * st.get('games', 0) + 2 * st.get('wins', 0))

    def norm_loadout(self, lo, pts):
        lo = lo or {}
        cls = lo.get('cls') if lo.get('cls') in CLASSES else 'medium'
        gun = lo.get('gun') if lo.get('gun') in GUNS else 'smoky'
        pt = int(clamp(num(lo.get('pt')), 0, 40))
        up_in = lo.get('up') or {}
        up = {k: int(clamp(num(up_in.get(k)), 0, 5)) for k in ('engine', 'armor', 'gun', 'reload')}
        while sum(up.values()) > pts:
            k = max(up, key=lambda x: up[x])
            if up[k] <= 0:
                break
            up[k] -= 1
        return {'cls': cls, 'gun': gun, 'pt': pt, 'up': up}

    def set_loadout(self, aid, lo):
        acc = self.by_id.get(aid)
        if not acc:
            return False, 'Нет аккаунта', None
        new_lo = self.norm_loadout(lo, self.upgrade_points(acc))
        acc['lo'] = new_lo
        self.dirty = True
        return True, '', new_lo

    async def add_stats(self, aid, games=0, wins=0, kills=0, deaths=0, score=0):
        async with self.lock:
            acc = self.by_id.get(aid)
            if not acc:
                return
            st = acc['stats']
            st['games'] += games
            st['wins'] += wins
            st['kills'] += kills
            st['deaths'] += deaths
            st['score'] += score
            self.dirty = True

    # ---- баны
    @staticmethod
    def _ban_rec(until, reason):
        return {'until': until, 'reason': str(reason)[:80], 't': time.time()}

    async def ban(self, ip=None, aid=None, hours=24, reason=''):
        async with self.lock:
            until = 0 if hours <= 0 else time.time() + hours * 3600
            if ip:
                self.bans['ip'][ip] = self._ban_rec(until, reason)
            if aid:
                self.bans['acc'][str(aid)] = self._ban_rec(until, reason)
            self.dirty = True

    def ip_banned(self, ip):
        r = self.bans['ip'].get(ip)
        return bool(r and (r['until'] == 0 or r['until'] > time.time()))

    def acc_banned(self, acc):
        r = self.bans['acc'].get(str(acc['id']))
        if r and (r['until'] == 0 or r['until'] > time.time()):
            return r
        r = acc.get('banned')
        if r and (r.get('until', 0) == 0 or r.get('until', 0) > time.time()):
            return r
        return None

    @staticmethod
    def acc_muted(acc):
        """Мут чата: muted_until == 0 — навсегда, > времени — до срока."""
        m = acc.get('muted_until')
        if m is None:
            return False
        return m == 0 or m > time.time()

    def logout(self, token):
        """Выход из аккаунта: сессия удаляется, токен больше не действителен."""
        if token and self.sessions.pop(token, None) is not None:
            self.dirty = True
            return True
        return False


# ------------------------------------------------------------------ игрок
class Player:
    _seq = 0

    def __init__(self, conn):
        Player._seq += 1
        self.id = Player._seq
        self.conn = conn
        self.ip = conn.ip
        self.account_id = 0
        self.name = 'Игрок'
        self.room = None
        self.team = 0
        self.cls = 'medium'
        self.gun = 'smoky'
        self.base_gun = 'smoky'
        self.paint = 0
        self.up = dict(engine=0, armor=0, gun=0, reload=0)
        self.room_t = -1e9
        self.reset_match()

    def reset_match(self):
        self.is_jugg = False
        self.kills = 0
        self.deaths = 0
        self.score = 0
        self.gun = self.base_gun
        self.maxhp = self.base_maxhp()
        self.hp = self.maxhp
        self.alive = True
        self.respawn_at = 0.0
        self.ghost_until = now() + GHOST_S
        self.buffs = {}
        self.od = 0.0
        self.od_until = 0.0
        self.item_cd = {}
        self.next_shot = 0.0
        self.last_shot_t = -1e9
        self.allow = 12
        self.x = self.z = 0.0
        self.r = self.t = self.v = 0.0
        self.pos_ok = False
        self.last_st = 0.0
        self.susp = 0.0
        self.strikes = 0
        self.strike_t = 0.0
        self.flag = None
        self.has_ball = False

    def base_maxhp(self):
        return round(CLASSES[self.cls]['hp'] + self.up['armor'] * 12)

    def send(self, obj):
        if self.conn:
            self.conn.send(obj)

    def buff(self, k):
        b = self.buffs.get(k)
        if b and b[1] > now():
            return b[0]
        return 1.0

    def cooldown(self):
        c = GUNS[self.gun]['cooldown'] / 1000.0 * CLASSES[self.cls]['reload'] * (1 - self.up['reload'] * 0.06)
        return c * (JUGG['reload'] if self.is_jugg else 1)

    def max_damage(self):
        g = GUNS[self.gun]
        d = g['damage'] * CLASSES[self.cls]['dmg'] * (1 + self.up['gun'] * 0.07)
        d *= self.buff('damage')
        if now() < self.od_until:
            d *= 1.75
        if self.is_jugg:
            d *= JUGG['dmg']
        return d

    def max_speed(self):
        s = CLASSES[self.cls]['speed'] * (1 + self.up['engine'] * 0.06) * 1.55 * 1.22 * 1.22 * 1.22
        return s


# ------------------------------------------------------------------ комната
class Room:
    def __init__(self, mode):
        self.mode = mode
        self.mdef = MODES[mode]
        self.players = {}
        self.map_idx = -1
        self.state = 'idle'
        self.tick_n = 0
        self.ended_at = 0.0
        self.pending = {}
        self.new_match_objects()

    # ---------- состав
    def counts(self):
        b = sum(1 for p in self.players.values() if p.team == 0)
        return b, len(self.players) - b

    def try_add(self, p, pref):
        cap = CFG['room_capacity']
        if len(self.players) >= cap:
            return False, 'Комната заполнена (%d/%d)' % (len(self.players), cap)
        if not self.mdef['team']:
            return True, 0
        b, r = self.counts()
        half = cap // 2
        if pref not in (0, 1):
            return True, (0 if b <= r else 1)
        if (b if pref == 0 else r) >= half:
            return False, 'Эта команда заполнена (%d/%d)' % (half, half)
        return True, pref

    def add(self, p, team):
        if self.state == 'idle':
            self.start_match()
        p.room = self
        p.team = team
        self.players[p.id] = p
        p.reset_match()
        p.send(self.joined_msg(p))
        self.broadcast({'t': 'pl_join', 'p': self.pinfo(p)}, skip=p)

    def remove(self, p):
        if p.id not in self.players:
            return
        self.drop_carried(p)
        if p.is_jugg and self.mode == 'JUGG':
            self.jugg_clear(p)
        del self.players[p.id]
        p.room = None
        self.broadcast({'t': 'pl_leave', 'id': p.id})
        if not self.players:
            self.state = 'idle'
            self.new_match_objects()

    def leader(self):
        return min(self.players.values(), key=lambda q: q.id) if self.players else None

    def broadcast(self, obj, skip=None):
        frame = make_frame(json.dumps(obj, separators=(',', ':'), ensure_ascii=False))
        for q in self.players.values():
            if q is not skip and q.conn:
                q.conn.send_frame(frame)

    def ev(self, k, **kw):
        kw['t'] = 'ev'
        kw['k'] = k
        self.broadcast(kw)

    def pinfo(self, p):
        return {'id': p.id, 'n': p.name, 'tm': p.team, 'cls': p.cls, 'gun': p.gun, 'pt': p.paint,
                'hp': round(p.hp, 1), 'mx': p.maxhp, 'al': p.alive, 'k': p.kills, 'd': p.deaths,
                'j': p.is_jugg}

    # ---------- матч
    def new_match_objects(self):
        self.sc = {'b': 0, 'r': 0}
        self.fc = {'b': 0, 'r': 0}
        self.flags, self.points, self.mines, self.pickups, self.boxes = [], [], [], [], []
        self.ball = None
        self.asl = None
        self.jugg = {0: None, 1: None}
        self.jugg_timer = {0: 2.5, 1: 3.5}
        self.cp_timer = 0.0
        self.pickup_timer = 3.0
        self.obj_seq = 0
        self.pending = {}

    def current_map(self):
        return MAP_ORDER[self.map_idx % len(MAP_ORDER)]

    def start_match(self):
        self.map_idx += 1
        self.map = self.current_map()
        mp = MAPS[self.map]
        self.new_match_objects()
        self.state = 'play'
        self.time_left = float(self.mdef['time'])
        for p in self.players.values():
            p.reset_match()
        m = self.mode
        if m in ('CTF',):
            self.flags = [self.mk_flag(0, mp['blueFlag']), self.mk_flag(1, mp['redFlag'])]
        elif m == 'ASLT':
            atk = random.randint(0, 1)
            dfn = 1 - atk
            dpos = mp['blueFlag'] if dfn == 0 else mp['redFlag']
            apos = mp['blueFlag'] if atk == 0 else mp['redFlag']
            self.flags = [self.mk_flag(dfn, dpos)]
            mx = 30
            self.asl = dict(atk=atk, dfn=dfn, flagPos=dpos, zone=apos, tickets=mx, tmax=mx)
        elif m in ('CP', 'SIEGE'):
            self.points = [dict(id='ABC'[i], x=pt[0], z=pt[1], owner=None, prog=0.0, cap=None, act=(m == 'CP'))
                           for i, pt in enumerate(mp['points'][:3])]
            if m == 'SIEGE':
                self.points[1]['act'] = True
        elif m == 'RGB':
            self.ball = dict(x=0.0, z=0.0, c=None, vx=0.0, vz=0.0, life=30.0, zone=0)
            self.ball_new_zone()
        self.broadcast(self.joined_like('match'))

    def mk_flag(self, team, pos):
        return dict(team=team, hx=pos[0], hz=pos[1], x=pos[0], z=pos[1], c=None, drop=0.0)

    def joined_like(self, t):
        return {'t': t, 'room': self.mode, 'map': self.map, 'tl': round(self.time_left),
                'players': [self.pinfo(p) for p in self.players.values()],
                'asl': ({'atk': self.asl['atk'], 'dfn': self.asl['dfn'], 'tk': self.asl['tickets']} if self.asl else None),
                'o': self.obj_state(), 'sc': self.sc, 'fc': self.fc,
                'jg': {str(k): (v.id if v else 0) for k, v in self.jugg.items()},
                'mines': [dict(id=m['id'], x=m['x'], z=m['z'], tm=m['team']) for m in self.mines],
                'pk': [dict(id=q['id'], x=q['x'], z=q['z'], ty=q['ty']) for q in self.pickups],
                'bx': [dict(id=b['id'], x=b['x'], z=b['z']) for b in self.boxes]}

    def joined_msg(self, p):
        m = self.joined_like('joined')
        m['you'] = p.id
        m['team'] = p.team
        return m

    def finish(self, winner_team=None, winner_id=None, text=''):
        if self.state != 'play':
            return
        self.state = 'ended'
        self.ended_at = now()
        sb = sorted(({'id': p.id, 'n': p.name, 'tm': p.team, 'k': p.kills, 'd': p.deaths, 's': p.score}
                     for p in self.players.values()), key=lambda r: -r['s'])
        self.broadcast({'t': 'end', 'wt': winner_team, 'wid': winner_id, 'text': text, 'sb': sb,
                        'next': CFG['match_end_delay']})
        # статистика в аккаунты
        for p in self.players.values():
            if p.account_id and STORE is not None:
                win = (winner_team is not None and p.team == winner_team) or (winner_id is not None and p.id == winner_id)
                spawn(STORE.add_stats(p.account_id, games=1, wins=1 if win else 0,
                                      kills=p.kills, deaths=p.deaths, score=p.score))

    # ---------- урон / убийства
    def damage(self, v, raw, killer=None, slow=0):
        t = now()
        if not v.alive or t < v.ghost_until or self.state != 'play':
            return
        dmg = raw / (v.buff('armor') * CLASSES[v.cls]['armor'])
        if t < v.od_until:
            dmg *= 0.72
        if v.flag is not None:
            dmg *= 0.85
        if self.mode == 'ASLT' and self.asl and v.team == self.asl['dfn']:
            fp = self.asl['flagPos']
            if d2(v.x, v.z, fp[0], fp[1]) < 22:
                dmg *= 0.85
        v.hp -= dmg
        if killer and killer is not v and t >= killer.od_until:
            killer.od = clamp(killer.od + raw * 0.5, 0, 100)
        msg = {'t': 'hp', 'id': v.id, 'hp': round(max(0, v.hp), 1), 'by': killer.id if killer else 0, 'sl': slow}
        v.send(msg)
        if killer and killer is not v:
            killer.send(msg)
        if v.hp <= 0:
            self.kill(v, killer)

    def heal(self, p, amount):
        p.hp = min(p.maxhp, p.hp + amount)
        p.send({'t': 'hp', 'id': p.id, 'hp': round(p.hp, 1), 'by': 0, 'sl': 0})

    def kill(self, v, killer):
        v.alive = False
        v.hp = 0
        v.deaths += 1
        v.respawn_at = now() + RESPAWN_S
        v.pos_ok = False
        self.drop_carried(v)
        real = bool(killer and killer is not v and (not self.mdef['team'] or killer.team != v.team))
        if real:
            killer.kills += 1
            killer.score += 100
            killer.od = clamp(killer.od + 18, 0, 100)
            k = 'b' if killer.team == 0 else 'r'
            if self.mode == 'TDM':
                self.sc[k] += 10
            elif self.mode in ('CP', 'SIEGE'):
                self.sc[k] += 3
        self.broadcast({'t': 'dead', 'id': v.id, 'by': killer.id if (killer and killer is not v) else 0})
        if v.is_jugg:
            self.jugg_down(v, killer if real else None)
        if self.mode == 'ASLT' and self.asl and v.team == self.asl['atk']:
            self.asl['tickets'] = max(0, self.asl['tickets'] - 1)
            if self.asl['tickets'] in (10, 3):
                self.ev('tickets', n=self.asl['tickets'])
            if self.asl['tickets'] <= 0:
                self.finish(self.asl['dfn'], None, 'Оборона устояла: жизни атаки закончились')
        if self.mode == 'DM' and real and killer.kills >= MODES['DM']['target']:
            self.finish(None, killer.id, '%s набрал %d убийств' % (killer.name, killer.kills))

    # ---------- переносимые предметы
    def drop_carried(self, p):
        if p.flag is not None:
            f = p.flag
            f['c'] = None
            f['x'], f['z'] = p.x, p.z
            f['drop'] = 18.0
            p.flag = None
            self.ev('flag_drop', team=f['team'])
        if self.ball and self.ball['c'] == p.id:
            self.ball['c'] = None
            self.ball['x'], self.ball['z'] = p.x, p.z
            self.ball['vx'], self.ball['vz'] = random.uniform(-3, 3), random.uniform(-3, 3)
            p.has_ball = False
            self.ev('ball_drop')

    # ---------- Джаггернаут
    def jugg_make(self, p):
        p.is_jugg = True
        p.maxhp = p.hp = JUGG['hp']
        p.gun = 'railgun'
        self.jugg[p.team] = p
        self.ev('jugg_new', team=p.team, id=p.id)
        p.send({'t': 'hp', 'id': p.id, 'hp': p.hp, 'by': 0, 'sl': 0, 'mx': p.maxhp})

    def jugg_clear(self, p):
        p.is_jugg = False
        p.maxhp = p.base_maxhp()
        p.gun = p.base_gun
        if self.jugg.get(p.team) is p:
            self.jugg[p.team] = None

    def jugg_down(self, v, killer):
        team = v.team
        self.jugg_clear(v)
        self.jugg_timer[team] = JUGG['respawn']
        if killer and killer.team != team:
            self.sc['b' if killer.team == 0 else 'r'] += 1
        self.ev('jugg_down', team=team, by=(killer.id if killer else 0))

    # ---------- мяч
    def ball_new_zone(self):
        zs = MAPS[self.map]['zones']
        i = random.randrange(len(zs))
        b = self.ball
        b.update(x=float(zs[i][0]), z=float(zs[i][1]), c=None, vx=0.0, vz=0.0, life=30.0, zone=i)
        for p in self.players.values():
            p.has_ball = False
        self.ev('ball_new', zone=i)

    # ---------- главный тик
    def tick(self, dt):
        if self.state == 'idle':
            return
        self.tick_n += 1
        t = now()
        if self.state == 'ended':
            if t - self.ended_at >= CFG['match_end_delay']:
                self.start_match()
            return
        self.time_left -= dt
        for p in self.players.values():
            if not p.alive and t >= p.respawn_at:
                p.alive = True
                p.hp = p.maxhp = p.base_maxhp()
                p.ghost_until = t + GHOST_S
                p.buffs = {}
                p.od_until = 0
                p.pos_ok = False
                self.broadcast({'t': 'respawn', 'id': p.id, 'mx': p.maxhp})
        getattr(self, 'mode_' + self.mode)(dt)
        self.tick_mines(dt)
        self.tick_pickups(dt)
        if self.state == 'play' and self.time_left <= 0:
            self.time_up()
        if self.state == 'play' and self.tick_n % SNAP_EVERY == 0:
            self.broadcast(self.snapshot())

    def alive_pos(self):
        return [p for p in self.players.values() if p.alive and p.pos_ok]

    # ---------- режимы
    def mode_DM(self, dt):
        pass

    def mode_TDM(self, dt):
        self.check_score(600, 'Очки')

    def check_score(self, target, label):
        if self.sc['b'] >= target:
            self.finish(0, None, '%s: синие %d : %d красные' % (label, self.sc['b'], self.sc['r']))
        elif self.sc['r'] >= target:
            self.finish(1, None, '%s: синие %d : %d красные' % (label, self.sc['b'], self.sc['r']))

    @staticmethod
    def capture_step(pt, blue, red, dt, rate):
        cap = 0 if blue > red else (1 if red > blue else None)
        if cap is not None and cap != pt['owner']:
            n = blue if cap == 0 else red
            step = dt * rate * (1 + min(3, n) * 0.3)
            if pt['cap'] is not None and pt['cap'] != cap and pt['prog'] > 0:
                pt['prog'] = max(0.0, pt['prog'] - step * 1.5)
            else:
                pt['cap'] = cap
                pt['prog'] = min(100.0, pt['prog'] + step)
                if pt['prog'] >= 100:
                    return cap
        elif blue == 0 and red == 0:
            pt['prog'] = max(0.0, pt['prog'] - dt * 3)
            if pt['prog'] == 0:
                pt['cap'] = None
        elif cap == pt['owner']:
            pt['prog'] = max(0.0, pt['prog'] - dt * 6)
            if pt['prog'] == 0:
                pt['cap'] = None
        return None

    def point_counts(self, pt):
        b = r = 0
        for p in self.alive_pos():
            if d2(p.x, p.z, pt['x'], pt['z']) < 9:
                if p.team == 0:
                    b += 1
                else:
                    r += 1
        return b, r

    def mode_CP(self, dt):
        for pt in self.points:
            b, r = self.point_counts(pt)
            cap = self.capture_step(pt, b, r, dt, 13)
            if cap is not None:
                pt.update(owner=cap, prog=0.0, cap=None)
                self.ev('cap', pt=pt['id'], team=cap)
        self.cp_timer += dt
        if self.cp_timer >= 2:
            self.cp_timer -= 2
            for pt in self.points:
                if pt['owner'] is not None:
                    self.sc['b' if pt['owner'] == 0 else 'r'] += 2
        self.check_score(600, 'Очки')

    def mode_SIEGE(self, dt):
        for pt in self.points:
            if not pt['act']:
                continue
            b, r = self.point_counts(pt)
            cap = self.capture_step(pt, b, r, dt, 2.2)
            if cap is not None:
                pt.update(owner=cap, prog=0.0, cap=None, act=False)
                self.ev('cap', pt=pt['id'], team=cap)
                self.siege_advance(pt, cap)
        self.cp_timer += dt
        if self.cp_timer >= 1:
            self.cp_timer -= 1
            bl = sum(1 for p in self.points if p['owner'] == 0)
            rd = sum(1 for p in self.points if p['owner'] == 1)
            if bl > rd:
                self.sc['b'] += (bl - rd) * 3
            elif rd > bl:
                self.sc['r'] += (rd - bl) * 3
        self.check_score(1000, 'Осада')

    def siege_advance(self, done, cap):
        n = len(self.points)
        idx = self.points.index(done)
        for k in range(1, n + 1):
            c = self.points[(idx + k) % n]
            if c is not done and c['owner'] != cap:
                c.update(act=True, prog=0.0, cap=None)
                self.ev('siege_act', pt=c['id'])
                return
        self.sc['b' if cap == 0 else 'r'] += 100
        for c in self.points:
            c.update(owner=None, prog=0.0, cap=None, act=False)
        self.points[n // 2]['act'] = True
        self.ev('siege_all', team=cap)

    def mode_CTF(self, dt):
        self.flag_logic(dt, ctf=True)
        for team, key in ((0, 'b'), (1, 'r')):
            if self.fc[key] >= 5:
                self.finish(team, None, 'Флаги: синие %d : %d красные' % (self.fc['b'], self.fc['r']))
                return

    def flag_logic(self, dt, ctf):
        for f in self.flags:
            if f['c'] is None and d2(f['x'], f['z'], f['hx'], f['hz']) >= 2.5:
                f['drop'] -= dt
                if f['drop'] <= 0:
                    f['x'], f['z'] = f['hx'], f['hz']
                    self.ev('flag_ret', team=f['team'], by=0)
        for p in self.alive_pos():
            for f in self.flags:
                if f['c'] == p.id or f['c'] is not None:
                    continue
                if d2(p.x, p.z, f['x'], f['z']) >= 5:
                    continue
                grab = (f['team'] != p.team) if ctf else (p.team == self.asl['atk'])
                if grab:
                    f['c'] = p.id
                    p.flag = f
                    self.ev('flag_take', team=f['team'], by=p.id)
                elif d2(f['x'], f['z'], f['hx'], f['hz']) > 2.5:
                    f['x'], f['z'] = f['hx'], f['hz']
                    self.ev('flag_ret', team=f['team'], by=p.id)
            if p.flag is None:
                continue
            if ctf:
                mine = next((f for f in self.flags if f['team'] == p.team), None)
                if mine and mine['c'] is None and d2(p.x, p.z, mine['hx'], mine['hz']) < 6.5:
                    fl = p.flag
                    fl['c'] = None
                    fl['x'], fl['z'] = fl['hx'], fl['hz']
                    p.flag = None
                    self.fc['b' if p.team == 0 else 'r'] += 1
                    p.score += 200
                    self.ev('flag_cap', team=p.team, by=p.id)
            else:
                A = self.asl
                if p.team == A['atk'] and d2(p.x, p.z, A['zone'][0], A['zone'][1]) < 7.5:
                    fl = p.flag
                    fl['c'] = None
                    fl['x'], fl['z'] = fl['hx'], fl['hz']
                    p.flag = None
                    self.fc['b' if A['atk'] == 0 else 'r'] += 1
                    A['tickets'] = min(A['tmax'], A['tickets'] + 8)
                    p.score += 200
                    self.ev('flag_cap', team=p.team, by=p.id)
        for f in self.flags:
            if f['c'] is not None:
                c = self.players.get(f['c'])
                if c and c.alive:
                    f['x'], f['z'] = c.x, c.z
                else:
                    f['c'] = None

    def mode_ASLT(self, dt):
        self.flag_logic(dt, ctf=False)
        A = self.asl
        got = self.fc['b' if A['atk'] == 0 else 'r']
        if got >= MODES['ASLT']['target']:
            self.finish(A['atk'], None, 'Штурм удался: флагов %d/%d' % (got, MODES['ASLT']['target']))

    def mode_JUGG(self, dt):
        for team in (0, 1):
            cur = self.jugg[team]
            if cur and cur.alive:
                continue
            self.jugg[team] = None
            self.jugg_timer[team] -= dt
            if self.jugg_timer[team] > 0:
                continue
            pool = [p for p in self.players.values() if p.team == team and p.alive]
            if pool:
                self.jugg_make(random.choice(pool))
        self.check_score(10, 'Джаггернауты')

    def mode_RGB(self, dt):
        b = self.ball
        if b is None:
            return
        if b['c'] is None:
            b['x'] += b['vx'] * dt
            b['z'] += b['vz'] * dt
            fr = 0.92 ** (dt * 60)
            b['vx'] *= fr
            b['vz'] *= fr
            b['x'] = clamp(b['x'], -228, 228)
            b['z'] = clamp(b['z'], -228, 228)
            b['life'] -= dt
            for p in self.alive_pos():
                if d2(p.x, p.z, b['x'], b['z']) < 4.6:
                    b['c'] = p.id
                    p.has_ball = True
                    b['vx'] = b['vz'] = 0.0
                    b['life'] = 30.0
                    self.ev('ball_take', by=p.id)
                    break
            if b['c'] is None and b['life'] <= 0:
                self.ball_new_zone()
        else:
            c = self.players.get(b['c'])
            if not c or not c.alive:
                b['c'] = None
            else:
                b['x'], b['z'] = c.x, c.z
                mp = MAPS[self.map]
                base = mp['redBase'] if c.team == 0 else mp['blueBase']
                if d2(c.x, c.z, base[0], base[1]) < 10:
                    self.sc['b' if c.team == 0 else 'r'] += 1
                    c.score += 300
                    c.has_ball = False
                    self.ev('ball_goal', team=c.team, by=c.id)
                    self.ball_new_zone()
        self.check_score(5, 'Счёт')

    def time_up(self):
        m = self.mode
        if m == 'DM':
            best = max(self.players.values(), key=lambda p: p.kills, default=None)
            if best is None or best.kills <= 0:
                self.finish(None, None, 'Время вышло: ничья')
            else:
                self.finish(None, best.id, 'Время вышло')
        elif m == 'ASLT':
            self.finish(self.asl['dfn'], None, 'Оборона продержалась до конца')
        elif m == 'CTF':
            self.finish(*self.by_score(self.fc['b'], self.fc['r'], 'Время вышло'))
        else:
            self.finish(*self.by_score(self.sc['b'], self.sc['r'], 'Время вышло'))

    @staticmethod
    def by_score(b, r, text):
        w = 0 if b > r else (1 if r > b else -1)
        return (w if w >= 0 else None), None, '%s: %d : %d' % (text, b, r)

    # ---------- мины / бонусы / ящики
    def tick_mines(self, dt):
        t = now()
        for m in self.mines[:]:
            m['life'] -= dt
            if m['life'] <= 0:
                self.mines.remove(m)
                self.ev('mine_gone', id=m['id'])
                continue
            if t < m['arm']:
                continue
            hit = False
            for p in self.alive_pos():
                if p.id == m['owner']:
                    continue
                if self.mdef['team'] and p.team == m['team']:
                    continue
                if d2(p.x, p.z, m['x'], m['z']) < 2.3:
                    hit = True
                    break
            if hit:
                self.mines.remove(m)
                self.ev('mine_boom', id=m['id'], x=m['x'], z=m['z'])
                owner = self.players.get(m['owner'])
                for p in list(self.players.values()):
                    if not p.alive or p.id == m['owner'] or (self.mdef['team'] and p.team == m['team']):
                        continue
                    dd = d2(p.x, p.z, m['x'], m['z'])
                    if dd < 5.5:
                        self.damage(p, 85 * (1 - dd / 6.5), owner)

    def tick_pickups(self, dt):
        t = now()
        for q in self.pickups[:]:
            q['life'] -= dt
            if q['life'] <= 0:
                self.pickups.remove(q)
                self.ev('pk_gone', id=q['id'])
        for b in self.boxes[:]:
            if t - b['t0'] > 120:
                self.boxes.remove(b)
                self.ev('bx_gone', id=b['id'])
            elif t - b['t0'] > 4.0:
                for p in self.alive_pos():
                    if d2(p.x, p.z, b['x'], b['z']) < 4.5:
                        amt = 500 + random.randint(0, 299)
                        self.boxes.remove(b)
                        # кристаллы ящика начисляются на сервере (клиент только показывает)
                        if p.account_id:
                            acc = STORE.by_id.get(p.account_id)
                            if acc is not None:
                                acc['crystals'] = acc.get('crystals', 0) + amt
                                STORE.dirty = True
                        self.ev('bx_taken', id=b['id'], by=p.id, amt=amt)
                        break
        for q in self.pickups[:]:
            for p in self.alive_pos():
                if d2(p.x, p.z, q['x'], q['z']) < 4.0:
                    self.take_pickup(p, q)
                    break
        for k, pend in list(self.pending.items()):
            if t - pend['t0'] > 6:
                del self.pending[k]
        self.pickup_timer -= dt
        if self.pickup_timer <= 0:
            self.pickup_timer = random.uniform(8, 15)
            if len(self.pickups) + sum(1 for v in self.pending.values() if v['kind'] == 'pk') < 7:
                self.request_spot('pk', random.choice(PICKUPS))

    def take_pickup(self, p, q):
        if q not in self.pickups:
            return
        self.pickups.remove(q)
        t = now()
        ty = q['ty']
        if ty == 'repair':
            self.heal(p, p.maxhp * 0.45)
        elif ty == 'armor':
            p.buffs['armor'] = (1.7, t + 12)
        elif ty == 'damage':
            p.buffs['damage'] = (2.0, t + 12)
        elif ty == 'speed':
            p.buffs['speed'] = (1.55, t + 12)
        self.ev('pk_taken', id=q['id'], by=p.id, ty=ty)
        if ty == 'crystal' and p.account_id and STORE is not None:
            acc = STORE.by_id.get(p.account_id)
            if acc:
                acc['crystals'] = acc.get('crystals', 0) + 15
                STORE.dirty = True

    def request_spot(self, kind, extra, owner=None):
        ld = self.leader()
        if not ld:
            return
        self.obj_seq += 1
        sid = self.obj_seq
        self.pending[sid] = dict(kind=kind, extra=extra, owner=owner, t0=now())
        ld.send({'t': 'need_spot', 'id': sid, 'kind': kind})

    def spot_ok(self, x, z):
        """Спавн предметов: внутри игровой зоны и не на флагах/базах/точках карты."""
        if abs(x) > SPOT_LIMIT or abs(z) > SPOT_LIMIT:
            return False
        mp = MAPS.get(getattr(self, 'map', ''))
        if not mp:
            return True
        for pos in [mp['blueFlag'], mp['redFlag'], mp['blueBase'], mp['redBase']] + list(mp['points']) + list(mp['zones']):
            if d2(x, z, pos[0], pos[1]) < SPOT_CLEAR:
                return False
        return True

    def on_spot(self, p, m):
        ld = self.leader()
        if p is not ld:
            return
        sid = int(num(m.get('id')))
        pend = self.pending.pop(sid, None)
        if not pend:
            return
        x, z = num(m.get('x')), num(m.get('z'))
        if not self.spot_ok(x, z):
            tries = pend.get('try', 0) + 1
            if tries <= 3:                      # просим другую точку (ограниченное число раз)
                self.obj_seq += 1
                pend.update({'try': tries, 't0': now()})
                self.pending[self.obj_seq] = pend
                ld.send({'t': 'need_spot', 'id': self.obj_seq, 'kind': pend['kind']})
            return
        self.obj_seq += 1
        oid = self.obj_seq
        if pend['kind'] == 'pk':
            self.pickups.append(dict(id=oid, x=x, z=z, ty=pend['extra'], life=40.0))
            self.ev('pk_new', id=oid, x=x, z=z, ty=pend['extra'])
        else:
            self.boxes.append(dict(id=oid, x=x, z=z, t0=now()))
            self.ev('bx_new', id=oid, x=x, z=z, by=pend['owner'])

    # ---------- снапшот
    def obj_state(self):
        o = {}
        if self.flags:
            o['f'] = [[f['team'], round(f['x'], 1), round(f['z'], 1), f['c'] or 0] for f in self.flags]
        if self.points:
            o['p'] = [[pt['id'], -1 if pt['owner'] is None else pt['owner'],
                       round(pt['prog'] if pt['prog'] > 0 else (100 if pt['owner'] is not None else 0), 1),
                       -1 if pt['cap'] is None else pt['cap'], 1 if pt['act'] else 0] for pt in self.points]
        if self.ball:
            b = self.ball
            o['b'] = [round(b['x'], 1), round(b['z'], 1), b['c'] or 0, b['zone']]
        if self.asl:
            o['a'] = [self.asl['tickets'], self.asl['atk']]
        return o

    def snapshot(self):
        return {'t': 'snap', 'tl': int(self.time_left), 'sc': self.sc, 'fc': self.fc, 'o': self.obj_state(),
                'p': [[p.id, round(p.x, 2), round(p.z, 2), round(p.r, 3), round(p.t, 3), round(p.v, 2),
                       round(p.hp, 1), 1 if p.alive else 0, p.kills, p.deaths, int(p.od)] for p in self.players.values()]}

    def summary(self):
        b, r = self.counts()
        return {'id': self.mode, 'n': len(self.players), 'b': b, 'r': r, 'cap': CFG['room_capacity'],
                'map': getattr(self, 'map', MAP_ORDER[0]), 'tl': int(getattr(self, 'time_left', self.mdef['time'])),
                'st': self.state, 'team': self.mdef['team'],
                'pl': [[p.name, p.team] for p in self.players.values()]}


ROOMS = {}
CONNS = set()
STORE = None


# ------------------------------------------------------------------ обработка сообщений
async def on_auth(p, m):
    """Авторизация по WS: токен или логин+пароль (пароль — с rate-limit, как HTTP).
    Все поля проверяются по типам — мусор даёт auth_err, а не исключение."""
    acc = None
    token = None
    err = 'Неверные данные авторизации'
    tk, lg, pw = m.get('token'), m.get('login'), m.get('password')
    if tk is not None:
        if not isinstance(tk, str) or not (0 < len(tk) <= 128):
            p.send({'t': 'auth_err', 'err': err})
            return
        acc, token = STORE.auth_token(tk)
        if not acc:
            err = 'Сессия истекла, войдите снова'
    elif lg is not None or pw is not None:
        if not isinstance(lg, str) or not isinstance(pw, str) or not lg or not pw or len(lg) > 64 or len(pw) > 128:
            p.send({'t': 'auth_err', 'err': err})
            return
        if auth_limited(p.ip):
            p.send({'t': 'auth_err', 'err': 'Слишком много попыток входа. Подождите минуту.'})
            return
        ok, err, token = await STORE.login_user(lg, pw)
        if ok:
            acc, token = STORE.auth_token(token)
    if not acc:
        p.send({'t': 'auth_err', 'err': err})
        return
    ban = STORE.acc_banned(acc)
    if ban:
        p.send({'t': 'auth_err', 'err': 'Аккаунт заблокирован: ' + str(ban.get('reason', ''))})
        return
    # одна активная сессия на аккаунт
    for c in list(CONNS):
        q = c.player
        if q is not None and q is not p and q.account_id == acc['id']:
            q.send({'t': 'kicked', 'r': 'Вход выполнен с другого устройства'})
            q.conn.close()
    if p.room is not None and p.account_id != acc['id']:
        p.room.remove(p)          # смена аккаунта на живом соединении — не оставляем чужой танк в бою
    p.account_id = acc['id']
    p.name = acc['name']
    p.send({'t': 'auth_ok', 'id': acc['id'], 'name': acc['name'], 'token': token,
            'lo': acc.get('lo') or Store.DEF_LO.copy(), 'stats': acc.get('stats') or {},
            'up_pts': STORE.upgrade_points(acc)})


async def on_admin(p, m):
    # constant-time сравнение ключа — как в HTTP админ-API; перебор блокирует IP
    if not CFG['admin_key'] or admin_blocked(p.ip):
        return
    if not safe_eq(str(m.get('key', '')), CFG['admin_key']):
        admin_fail(p.ip)
        return
    admin_ok_ip(p.ip)
    cmd = m.get('cmd')
    async with STORE.lock:
        if cmd == 'unban_ip':
            STORE.bans['ip'].pop(str(m.get('ip')), None)
            STORE.dirty = True
        elif cmd == 'unban_acc':
            STORE.bans['acc'].pop(str(m.get('aid')), None)
            STORE.dirty = True
        elif cmd == 'list':
            p.send({'t': 'admin_ok', 'cmd': cmd, 'bans': copy.deepcopy(STORE.bans)})
            return
        else:
            return
    p.send({'t': 'admin_ok', 'cmd': cmd})


def on_loadout(p, m):
    if not p.account_id:
        return
    ok, err, lo = STORE.set_loadout(p.account_id, m.get('lo') or {})
    if ok:
        acc = STORE.by_id.get(p.account_id)
        p.send({'t': 'loadout_ok', 'lo': lo, 'up_pts': Store.upgrade_points(acc)})
    else:
        p.send({'t': 'loadout_err', 'err': err})


async def handle(p: Player, m: dict):
    t = m.get('t')
    room = p.room
    if t == 'auth':
        await on_auth(p, m)
        return
    if t == 'ping':
        p.send({'t': 'pong', 'c': m.get('c')})
        return
    if CFG['auth_required'] and not p.account_id:
        p.send({'t': 'auth_err', 'err': 'Требуется авторизация'})
        return
    if t == 'admin':
        await on_admin(p, m)
    elif t == 'hello':
        p.send({'t': 'welcome', 'id': p.id, 'rooms': [r.summary() for r in ROOMS.values()]})
    elif t == 'rooms':
        p.send({'t': 'rooms', 'rooms': [r.summary() for r in ROOMS.values()]})
    elif t == 'join':
        on_join(p, m)
    elif t == 'leave':
        on_leave(p)
    elif t == 'chat':
        on_chat(p, room, m)          # работает и в лобби
    elif t == 'loadout':
        on_loadout(p, m)             # смена лоадаута — из лобби (раньше блокировалось `room is None`)
    elif room is None:
        return
    elif t == 'st':
        on_state(p, m)
    elif t == 'shot':
        on_shot(p, m)
    elif t == 'hit':
        on_hit(p, room, m)
    elif t == 'item':
        on_item(p, room, m)
    elif t == 'od':
        if p.alive and p.od >= 100 and now() >= p.od_until:
            p.od = 0
            p.od_until = now() + 8
    elif t == 'mine':
        on_mine(p, room, m)
    elif t == 'gold':
        if p.alive and now() >= p.item_cd.get('gold', 0):
            p.item_cd['gold'] = now() + ITEM_CD['gold']
            room.request_spot('bx', None, owner=p.id)
    elif t == 'spot':
        room.on_spot(p, m)
    elif t == 'pick':
        on_pick(p, room, m)
    elif t == 'pass':
        on_pass(p, room, m)


def on_leave(p):
    if p.room is None:
        return
    t = now()
    if t - p.room_t < ROOM_CHANGE_CD:      # анти-спам пересозданием матчей
        return
    p.room_t = t
    p.room.remove(p)


def on_join(p, m):
    room = ROOMS.get(str(m.get('room')))
    if not room:
        p.send({'t': 'join_err', 'r': 'Нет такой комнаты'})
        return
    if p.room is room:
        return  # уже здесь — повторный join (restartBattle) безвреден
    if now() - p.room_t < ROOM_CHANGE_CD:
        p.send({'t': 'join_err', 'r': 'Слишком часто. Подождите пару секунд.'})
        return
    # переход из другой комнаты: аккуратно покидаем старую, а не молча игнорируем
    if p.room is not None:
        p.room.remove(p)
    # лоадаут строго с сервера (из аккаунта) — клиентские lo игнорируются
    acc = STORE.by_id.get(p.account_id) if p.account_id else None
    lo = (acc or {}).get('lo') or {}
    p.name = clean_name((acc or {}).get('name') or p.name)
    p.cls = lo.get('cls') if lo.get('cls') in CLASSES else 'medium'
    p.base_gun = lo.get('gun') if lo.get('gun') in GUNS else 'smoky'
    p.paint = int(clamp(num(lo.get('pt')), 0, 40))
    up = lo.get('up') or {}
    # clamp 0..5 — как в norm_loadout (раньше тут пропускали до 10)
    p.up = {k: int(clamp(num(up.get(k)), 0, 5)) for k in ('engine', 'armor', 'gun', 'reload')}
    pref = m.get('team', -1)
    ok, res = room.try_add(p, pref if pref in (0, 1) else -1)
    if not ok:
        p.send({'t': 'join_err', 'r': res})
        return
    p.room_t = now()
    room.add(p, res)
    log.info('%s (#%d, acc#%s) -> %s team=%s', p.name, p.id, p.account_id, room.mode, res)


def ang_diff(a, b):
    """Кратчайшая разница углов a-b в диапазоне [-pi, pi]."""
    return (a - b + math.pi) % (2 * math.pi) - math.pi


def on_state(p, m):
    if not p.alive or p.room.state != 'play':
        return
    t = now()
    x = clamp(num(m.get('x')), -230, 230)
    z = clamp(num(m.get('z')), -230, 230)
    nr = num(m.get('r'))
    na = num(m.get('a'))
    if p.pos_ok and p.last_st:
        dt = max(0.05, min(1.0, t - p.last_st))   # нижняя граница: пачки пакетов не дают allow≈0
        dist = d2(x, z, p.x, p.z)
        allow = p.max_speed() * p.buff('speed') * dt * 1.2 + 1
        if dist > allow:
            # страйки старше 2 минут забываются: лаг/плохой пинг не копит бан
            if p.strike_t and t - p.strike_t > 120:
                p.strikes = 0
                p.susp = 0.0
            p.susp += dist - allow
            if p.susp > 40:
                p.strikes += 1
                p.susp = 0
                p.strike_t = t
                p.send({'t': 'fix', 'x': round(p.x, 2), 'z': round(p.z, 2)})
                if p.strikes >= 6:
                    log.warning('ban %s (#%d): speed hack', p.name, p.id)
                    spawn(STORE.ban(ip=p.ip, aid=p.account_id or None,
                                    hours=24, reason='speed-hack'))
                    p.conn.close()
                return
        else:
            p.susp = max(0.0, p.susp - dt * 6)
        # угловая скорость корпуса/башни: рывок обрезается до физического лимита
        lim_h = HULL_TURN_MAX * dt + ANGLE_SLACK
        lim_t = TURRET_TURN_MAX * dt + ANGLE_SLACK
        dr = ang_diff(nr, p.r)
        if abs(dr) > lim_h:
            nr = p.r + math.copysign(lim_h, dr)
        da = ang_diff(na, p.t)
        if abs(da) > lim_t:
            na = p.t + math.copysign(lim_t, da)
    p.x, p.z = x, z
    p.r = nr
    p.t = na
    p.v = clamp(num(m.get('v')), -60, 60)
    p.last_st = t
    p.pos_ok = True


def on_shot(p, m):
    if not p.alive or p.room.state != 'play':
        return
    t = now()
    if t < p.next_shot:
        return
    shots = m.get('s')
    if not isinstance(shots, list):
        return
    g = GUNS[p.gun]
    out = []
    for s in shots[:g['count']]:
        if isinstance(s, list) and len(s) == 6:
            out.append([round(num(v), 2) for v in s])
    if not out:
        return
    # спуф происхождения: выстрел должен вылетать из позиции самого танка
    if p.pos_ok:
        for s in out:
            if d2(s[0], s[1], p.x, p.z) > SHOT_ORIGIN_MAX:
                log.debug('shot origin spoof %s (#%d)', p.name, p.id)
                return
    p.next_shot = t + p.cooldown() * 0.9
    p.last_shot_t = t
    p.allow = min(40, p.allow + g['count'] * (3 + (8 if g['splash'] else 0)))
    p.room.broadcast({'t': 'shot', 'id': p.id, 's': out}, skip=p)


def on_hit(p, room, m):
    if not p.alive or room.state != 'play':
        return
    v = room.players.get(int(num(m.get('v'))))
    if v is None or v is p or not v.alive:
        return
    if room.mdef['team'] and v.team == p.team:
        return
    if p.allow < 1:
        return
    g = GUNS[p.gun]
    if p.pos_ok and v.pos_ok:
        dist = d2(p.x, p.z, v.x, v.z)
        # геометрии карт на сервере нет -> LOS не проверить; вместо неё жёсткие лимиты:
        # дальность и «снаряд мог долететь» (попадание только вскоре после реального выстрела)
        if dist > min(HIT_MAX_DIST, g['speed'] * HIT_RANGE_K + 20):
            return
        if now() - p.last_shot_t > dist / g['speed'] + HIT_FLIGHT_SLACK:
            return
    p.allow -= 1
    raw = clamp(num(m.get('d')), 0, p.max_damage() * 1.02)
    if raw <= 0:
        return
    room.damage(v, raw, p, g['slow'])


def on_item(p, room, m):
    k = m.get('k')
    if k not in ('repair', 'armor', 'damage', 'speed') or not p.alive:
        return
    t = now()
    if t < p.item_cd.get(k, 0):
        return
    p.item_cd[k] = t + ITEM_CD[k]
    if k == 'repair':
        room.heal(p, p.maxhp * 0.65)
    elif k == 'armor':
        p.buffs['armor'] = (1.8, t + 12)
    elif k == 'damage':
        p.buffs['damage'] = (2.0, t + 12)
    else:
        p.buffs['speed'] = (1.55, t + 12)


def on_mine(p, room, m):
    t = now()
    if not p.alive or t < p.item_cd.get('mine', 0):
        return
    x, z = num(m.get('x')), num(m.get('z'))
    if p.pos_ok and d2(x, z, p.x, p.z) > 12:
        return
    p.item_cd['mine'] = t + ITEM_CD['mine']
    room.obj_seq += 1
    mine = dict(id=room.obj_seq, x=clamp(x, -230, 230), z=clamp(z, -230, 230), owner=p.id, team=p.team,
                arm=t + 0.9, life=90.0)
    room.mines.append(mine)
    room.ev('mine_add', id=mine['id'], x=mine['x'], z=mine['z'], tm=p.team, o=p.id)


def on_pick(p, room, m):
    if not p.alive:
        return
    pid = int(num(m.get('id')))
    for q in room.pickups:
        if q['id'] == pid:
            if p.pos_ok and d2(p.x, p.z, q['x'], q['z']) > 6:
                return
            room.take_pickup(p, q)
            return


def on_pass(p, room, m):
    b = room.ball
    if not b or b['c'] != p.id or not p.alive:
        return
    dx, dz = num(m.get('dx')), num(m.get('dz'))
    n = math.hypot(dx, dz) or 1.0
    b['c'] = None
    b['x'], b['z'] = p.x, p.z
    b['vx'], b['vz'] = dx / n * 24, dz / n * 24
    b['life'] = 30.0
    p.has_ball = False
    room.ev('ball_pass', by=p.id)


# ------------------------------------------------------------------ авто-модерация чата
# Транслит-нормализация: перебить «куплю мefь» и «н аркотики» невозможно.
_CYR_TBL = str.maketrans({
    'a': 'а', 'b': 'в', 'c': 'с', 'e': 'е', 'h': 'н', 'k': 'к', 'm': 'м', 'o': 'о',
    'p': 'р', 't': 'т', 'x': 'х', 'y': 'у', 'u': 'и', 'i': 'и', 'j': 'и', 'd': 'д',
    'g': 'г', 'l': 'л', 'r': 'г', 's': 'с', 'v': 'у', 'n': 'п', 'q': 'к', 'w': 'ш',
    'f': 'ф', 'z': 'з',
    '0': 'о', '3': 'з', '4': 'ч', '6': 'б', '9': 'я', '@': 'а', '$': 'с', '+': 'т',
})
_LAT_TBL = str.maketrans({
    'а': 'a', 'в': 'b', 'с': 'c', 'е': 'e', 'к': 'k', 'м': 'm', 'н': 'h', 'о': 'o',
    'р': 'p', 'т': 't', 'х': 'x', 'у': 'y', 'и': 'u', 'д': 'g', 'л': 'l', 'п': 'n',
    'г': 'r', 'ф': 'f', 'з': 'z', 'ш': 'w',
})
_CYR_ALPHA = 'абвгдежзийклмнопрстуфхцчшщъыьэюя'
_LAT_ALPHA = 'abcdefghijklmnopqrstuvwxyz'


def _compact(s, cyr=True):
    """Нормализация текста для сравнения с банвордом: нижний регистр, ё→е,
    латиница/цифры-подделки → кириллица (или наоборот), повторы букв схлопываются,
    всё не-буквенное — разделитель. «Меfедрон0н» и «м ефедрон» дают «мефедрон»."""
    s = (s or '').lower().replace('ё', 'е')
    s = s.translate(_CYR_TBL if cyr else _LAT_TBL)
    alpha = _CYR_ALPHA if cyr else _LAT_ALPHA
    s = ''.join(ch if ch in alpha else (' ' if ch.isspace() or not ch.isalnum() else '')
                for ch in s)
    return re.sub(r'(.)\1+', r'\1', s)          # «сссууукаа» → «сука»


def _wprep(w):
    """Ленивый кэш нормализованных форм и регулярок для коротких слов."""
    if 'cc' not in w:
        cc = _compact(w['w'], True)
        cl = _compact(w['w'], False)

        def _rx(c):
            if not c or len(c) >= 5:
                return None
            try:
                return re.compile(r'(?<![а-яa-z])' + re.escape(c) + r'(?![а-яa-z])')
            except re.error:
                return False
        w['cc'], w['cl'] = cc, cl
        w['rc'], w['rl'] = _rx(cc), _rx(cl)
    return w


def _match_word(w, sp, ns, short_sp):
    c = w['cc']
    if c:
        if len(c) >= 5:
            if c in ns or c in sp:
                return True
        elif (w['rc'] and w['rc'].search(short_sp)) or ns == c:
            return True
    c = w['cl']
    if c:
        if len(c) >= 5:
            if c in ns or c in sp:
                return True
        elif (w['rl'] and w['rl'].search(short_sp)) or ns == c:
            return True
    return False


def check_text(text):
    """Мгновенная проверка текста по списку запрещённых слов.
    Возвращает список совпавших слов (dict из STORE.banwords)."""
    if not STORE.banwords:
        return []
    sp_c = _compact(text, True)
    ns_c = re.sub(r'\s+', '', sp_c)
    sp_l = _compact(text, False)
    ns_l = re.sub(r'\s+', '', sp_l)
    hits = []
    for w in STORE.banwords:
        if _match_word(_wprep(w), sp_c, ns_c, sp_c) or _match_word(_wprep(w), sp_l, ns_l, sp_l):
            hits.append(w)
    return hits


def censor_text(text):
    """Маскировка запрещённых слов «***» (действие censor) — по словам."""
    def sub(m):
        t = m.group(0)
        tc = _compact(t, True)
        for w in STORE.banwords:
            w = _wprep(w)
            c = w['cc']
            if c and (len(c) >= 5 and (c in tc) or (w['rc'] and w['rc'].search(tc))):
                return '***'
        return t
    return re.sub(r'\S+', sub, text)


def name_allowed(name):
    """Имя/логин допустимы, если фильтр ничего не нашёл."""
    return not check_text(name)


def chatlog_add(p, room, ch, text, act):
    STORE.chatlog.append({'ts': round(time.time(), 1), 'n': p.name, 'aid': p.account_id,
                          'ip': p.ip, 'room': room.mode if room else None, 'ch': ch,
                          'm': str(text)[:200], 'act': act})
    if len(STORE.chatlog) > CHATLOG_MAX:
        del STORE.chatlog[:len(STORE.chatlog) - CHATLOG_MAX]


def modlog_add(src, act, who, info=''):
    STORE.modlog.append({'ts': round(time.time(), 1), 'src': src, 'act': act,
                         'who': str(who)[:40], 'info': str(info)[:120]})
    if len(STORE.modlog) > MODLOG_MAX:
        del STORE.modlog[:len(STORE.modlog) - MODLOG_MAX]


def warn_count(acc):
    decay = float(STORE.modset.get('warn_decay_h', 48)) * 3600
    t = time.time()
    lst = [w for w in (acc.get('warns') or []) if t - w < decay]
    acc['warns'] = lst
    return len(lst)


def sys_chat(p, text):
    p.send({'t': 'chat', 'id': 0, 'n': 'СИСТЕМА', 'tm': 0, 'c': 'all', 'm': text})


def note_warn(p, reason, source='auto'):
    """Предупреждение игроку + эскалация: мут → бан → вечный бан (настройки в админке)."""
    acc = STORE.by_id.get(p.account_id) if p.account_id else None
    if acc is None:
        return
    acc.setdefault('warns', []).append(time.time())
    STORE.dirty = True
    n = warn_count(acc)
    ms = STORE.modset
    sys_chat(p, '⚠️ Предупреждение %d/%s: %s' % (n, ms.get('ban_at', 5) or '∞', reason))
    modlog_add(source, 'warn', p.name, reason)
    ban_hours = float(ms.get('ban_hours', 24))
    if ms.get('permaban_at', 8) and n >= ms['permaban_at']:
        spawn(_auto_ban(p, 0, 'Превышен лимит предупреждений (%d)' % n))
    elif ms.get('ban_at', 5) and n >= ms['ban_at']:
        spawn(_auto_ban(p, ban_hours, 'Превышен лимит предупреждений (%d)' % n))
    elif ms.get('mute_at', 3) and n >= ms['mute_at']:
        _auto_mute(p, float(ms.get('mute_minutes', 30)),
                   'Превышен лимит предупреждений (%d)' % n)


async def _auto_ban(p, hours, reason):
    await STORE.ban(ip=p.ip, aid=p.account_id or None, hours=hours, reason=reason)
    modlog_add('auto', 'ban', p.name, '%s (%s)' % (reason, 'навсегда' if hours <= 0 else '%.0fч' % hours))
    sys_chat(p, '⛔ %s' % ('Аккаунт заблокирован навсегда: ' if hours <= 0 else
                           'Аккаунт заблокирован на %.0f ч: ' % hours) + reason)
    for c in list(CONNS):
        if c.player is p:
            c.close()
            break


def _auto_mute(p, minutes, reason):
    acc = STORE.by_id.get(p.account_id) if p.account_id else None
    if acc is None:
        return
    acc['muted_until'] = 0 if minutes <= 0 else time.time() + minutes * 60
    STORE.dirty = True
    modlog_add('auto', 'mute', p.name, reason)
    sys_chat(p, '🔇 Чат заблокирован на %.0f мин: %s' % (minutes, reason))


_chat_times = {}   # p.id -> [ts сообщений] — окно антифлуда


def flood_check(p):
    """Антифлуд: слишком много сообщений подряд → авто-мут. True = сообщение пропустить."""
    ms = STORE.modset
    window = float(ms.get('flood_window_s', 10) or 0)
    limit = int(ms.get('flood_msgs', 8) or 0)
    if limit <= 0 or window <= 0:
        return True
    t = time.time()
    lst = _chat_times.setdefault(p.id, [])
    lst.append(t)
    while lst and t - lst[0] > window:
        lst.pop(0)
    if len(lst) > limit:
        lst.clear()
        minutes = float(ms.get('flood_mute_min', 5) or 0)
        if minutes > 0 and p.account_id:
            _auto_mute(p, minutes, 'Флуд в чате')
        else:
            sys_chat(p, '🚫 Слишком много сообщений подряд — притормози.')
        modlog_add('auto', 'flood', p.name, '%d сообщений за %d с' % (limit + 1, window))
        return False
    return True


def mod_check(p, text, room, ch):
    """Фильтр чата: censor → пропустить замаскированный текст,
    block/mute/ban → сообщение не доходит, игрок наказывается. Возвращает итоговый текст."""
    hits = check_text(text)
    if not hits:
        chatlog_add(p, room, ch, text, 'ok')
        return text
    strongest = max((MOD_ACTIONS.index(w.get('a', 'block')) for w in hits))
    action = MOD_ACTIONS[strongest]
    chatlog_add(p, room, ch, text, action)
    word = hits[0]['w']
    if STORE.modset.get('enabled', True):
        if action == 'censor':
            return censor_text(text)
        if action == 'ban':
            sys_chat(p, '⛔ Сообщение заблокировано: запрещённый контент. Бан.')
            spawn(_auto_ban(p, float(STORE.modset.get('auto_ban_hours', 24)),
                            'Запрещённый контент в чате'))
            return None
        if action == 'mute':
            _auto_mute(p, float(STORE.modset.get('mute_minutes', 30)), 'Запрещённое слово в чате')
            sys_chat(p, '🚫 Сообщение заблокировано фильтром.')
            return None
        # block
        sys_chat(p, '🚫 Сообщение заблокировано фильтром (запрещённое слово).')
        note_warn(p, 'Запрещённое слово в чате', 'auto-filter')
    else:
        modlog_add('filter-off', 'seen', p.name, word)
    return None


_last_chat = {}


def on_chat(p, room, m):
    # мут чата: сообщения не доходят никуда, игроку — одно пояснение
    acc = STORE.by_id.get(p.account_id) if p.account_id else None
    if acc is not None and STORE.acc_muted(acc):
        mu = acc.get('muted_until')
        until = 'навсегда' if mu == 0 else 'до ' + time.strftime('%d.%m %H:%M', time.localtime(mu))
        p.send({'t': 'chat', 'id': 0, 'n': 'СИСТЕМА', 'tm': 0, 'c': 'all',
                'm': 'Чат недоступен: мут ' + until})
        return
    t = now()
    if t - _last_chat.get(p.id, 0) < 0.6:
        return
    _last_chat[p.id] = t
    raw = str(m.get('m', ''))[:400]
    raw = re.sub(r'<[^>]+>', '', raw)                 # HTML-теги
    raw = raw.replace('<', '').replace('>', '')       # остатки незакрытых тегов
    raw = re.sub(r'[\x00-\x1f\x7f]', ' ', raw)
    text = re.sub(r'\s+', ' ', raw).strip()[:120]
    if not text:
        return
    ch = 'team' if m.get('c') == 'team' and room is not None and room.mdef['team'] else 'all'
    # МГНОВЕННАЯ проверка по запрещённым словам — до доставки кому-либо.
    # fail-open: если сам фильтр упал, сообщение уходит, но ошибка логируется.
    try:
        text = mod_check(p, text, room, ch)
    except Exception:
        log.exception('mod_check failed')
        try:
            chatlog_add(p, room, ch, text, 'ok')
        except Exception:
            pass
    if text is None:
        return
    if not flood_check(p):
        return
    if room is None:
        # лобби-чат: всем бездоменным соединениям
        msg = {'t': 'chat', 'id': p.id, 'n': p.name, 'tm': 0, 'c': 'all', 'm': text}
        frame = make_frame(json.dumps(msg, ensure_ascii=False, separators=(',', ':')))
        for c in list(CONNS):
            if c.player and c.player.room is None:
                c.send_frame(frame)
        return
    msg = {'t': 'chat', 'id': p.id, 'n': p.name, 'tm': p.team, 'c': ch, 'm': text}
    if ch == 'team':
        frame = make_frame(json.dumps(msg, ensure_ascii=False))
        for q in room.players.values():
            if q.team == p.team:
                q.conn.send_frame(frame)
    else:
        room.broadcast(msg)


# ------------------------------------------------------------------ HTTP API (регистрация/вход)
AUTH_TRIES = {}
_AUTH_GW = [0.0, 0]          # глобальное окно: [начало, счётчик]


def auth_limited(ip):
    """Лимит попыток входа/регистрации: на IP и глобально (защита от
    распределённого брутфорса с множества IP)."""
    t = time.time()
    if t - _AUTH_GW[0] >= 60:
        _AUTH_GW[0], _AUTH_GW[1] = t, 0
    _AUTH_GW[1] += 1
    if _AUTH_GW[1] > CFG['auth_global_per_min']:
        return True
    lst = AUTH_TRIES.get(ip)
    if lst is None:
        lst = AUTH_TRIES[ip] = []
    while lst and t - lst[0] > 60:
        lst.pop(0)
    if len(lst) >= CFG['auth_per_min']:
        return True
    lst.append(t)
    if len(AUTH_TRIES) > 5000:
        for k in [k for k, v in AUTH_TRIES.items() if not v or t - v[-1] > 300]:
            AUTH_TRIES.pop(k, None)
    return False


def profile_json(acc, token):
    return {'ok': True, 'token': token, 'id': acc['id'], 'name': acc['name'],
            'lo': acc['lo'], 'stats': acc['stats'], 'up_pts': Store.upgrade_points(acc)}


async def api_register(ip, body):
    try:
        m = json.loads(body)
    except Exception:
        return 400, {'ok': False, 'err': 'Некорректный JSON'}
    if not isinstance(m, dict):
        return 400, {'ok': False, 'err': 'Некорректный запрос'}
    if auth_limited(ip):
        return 429, {'ok': False, 'err': 'Слишком много попыток. Подождите минуту.'}
    ok, err, token = await STORE.register(m.get('login', ''), str(m.get('password', '')), m.get('name'))
    if not ok:
        return 400, {'ok': False, 'err': err}
    acc, _ = STORE.auth_token(token)
    log.info('register: %s (acc#%d) ip=%s', acc['login'], acc['id'], ip)
    return 200, profile_json(acc, token)


async def api_login(ip, body):
    try:
        m = json.loads(body)
    except Exception:
        return 400, {'ok': False, 'err': 'Некорректный JSON'}
    if not isinstance(m, dict):
        return 400, {'ok': False, 'err': 'Некорректный запрос'}
    if auth_limited(ip):
        return 429, {'ok': False, 'err': 'Слишком много попыток. Подождите минуту.'}
    ok, err, token = await STORE.login_user(m.get('login', ''), str(m.get('password', '')))
    if not ok:
        obj = {'ok': False, 'err': err}
        # структурированные данные бана — для страницы /banned (причина и срок)
        if 'заблокирован' in str(err).lower():
            acc = STORE.accounts.get(clean_login(m.get('login', '')).lower())
            ban = STORE.acc_banned(acc) if acc else None
            if ban:
                obj['ban'] = {'reason': str(ban.get('reason', '')), 'until': num(ban.get('until', 0))}
        return 401, obj
    acc, _ = STORE.auth_token(token)
    return 200, profile_json(acc, token)


def _ban_json(rec, source):
    return {'banned': True, 'source': source,
            'reason': str(rec.get('reason', '')), 'until': float(num(rec.get('until', 0)))}


async def api_baninfo(ip, body):
    """Информация о блокировке для страницы /banned: сначала бан аккаунта по
    токену сессии, иначе — бан IP. Доступна и с забаненного IP."""
    try:
        m = json.loads(body.decode('utf-8')) if body else {}
    except Exception:
        m = {}
    if not isinstance(m, dict):
        m = {}
    token = m.get('token')
    if isinstance(token, str) and 0 < len(token) <= 128:
        acc, _ = STORE.auth_token(token)
        if acc is not None:
            ban = STORE.acc_banned(acc)
            if ban:
                j = {'ok': True}
                j.update(_ban_json(ban, 'account'))
                j['hasAccount'] = True
                return 200, j
    rec = STORE.bans['ip'].get(ip)
    if rec and (rec.get('until', 0) == 0 or rec.get('until', 0) > time.time()):
        j = {'ok': True, 'hasAccount': bool(isinstance(token, str) and token)}
        j.update(_ban_json(rec, 'ip'))
        return 200, j
    return 200, {'ok': True, 'banned': False}


async def api_delete_account(ip, body):
    """Самоудаление аккаунта со страницы блокировки: только по валидной сессии."""
    try:
        m = json.loads(body.decode('utf-8')) if body else {}
    except Exception:
        m = {}
    token = m.get('token') if isinstance(m, dict) else None
    if not isinstance(token, str) or not token or len(token) > 128:
        return 400, {'ok': False, 'err': 'Нет активной сессии — удаление недоступно'}
    acc, _ = STORE.auth_token(token)
    if acc is None:
        return 401, {'ok': False, 'err': 'Сессия истекла — удаление недоступно'}
    aid, login = acc['id'], acc['login']
    async with STORE.lock:
        STORE.accounts.pop(login.lower(), None)
        STORE.by_id.pop(aid, None)
        STORE.sessions = {tk: s for tk, s in list(STORE.sessions.items()) if s.get('aid') != aid}
        STORE.dirty = True
    modlog_add('user', 'self-delete', login, 'удалён со страницы блокировки')
    for c in list(CONNS):
        q = c.player
        if q is not None and q.account_id == aid:
            q.send({'t': 'kicked', 'r': 'Аккаунт удалён'})
            if q.room:
                q.room.remove(q)
            c.close()
    log.info('self-delete: %s (#%d) ip=%s', login, aid, ip)
    return 200, {'ok': True}


# ------------------------------------------------------------------ статика
STATIC_CACHE = {}
# явные типы: mimetypes на Windows тянет типы из реестра и может врать
MIME_OVERRIDES = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.mjs': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
    '.webp': 'image/webp', '.ico': 'image/x-icon',
    '.woff2': 'font/woff2', '.ttf': 'font/ttf', '.mp3': 'audio/mpeg',
    '.ogg': 'audio/ogg', '.wav': 'audio/wav',
}


STATIC_ALLOWED = {e for e in MIME_OVERRIDES if e != '.json'} | {'.map', '.txt'}


def static_response(path: str, accept_gzip: bool, head: bool):
    root = (BASE / CFG['static_dir']).resolve()
    rel = unquote(path.split('?', 1)[0]).lstrip('/')
    if rel in ('', 'index.html'):
        rel = 'game.html'
    f = (root / rel).resolve()
    if root not in f.parents and f != root:
        return 403, b'Forbidden', 'text/plain', {}
    # белый список: НЕ отдаём config.json (admin_key), server.py, data/*.json (сессии/хэши), dot-файлы
    if f.suffix.lower() not in STATIC_ALLOWED or any(part.startswith('.') for part in f.relative_to(root).parts):
        return 404, b'Not found', 'text/plain', {}
    if not f.is_file():
        return 404, b'Not found', 'text/plain', {}
    ctype = MIME_OVERRIDES.get(f.suffix.lower()) or mimetypes.guess_type(str(f))[0] \
        or 'application/octet-stream'
    if f.suffix.lower() == '.html':
        ctype = 'text/html; charset=utf-8'
    st = f.stat()
    key = (str(f), st.st_mtime_ns)
    ext = f.suffix.lower()
    hdr = {'Cache-Control': 'no-cache' if ext in ('.html', '.js') else 'public, max-age=3600'}
    entry = STATIC_CACHE.get(key)
    if entry is None:
        if len(STATIC_CACHE) > 64:  # защита от разрастания кэша
            STATIC_CACHE.clear()
        body = f.read_bytes()
        if ext in ('.html', '.js', '.css', '.json') and len(body) > 1024:
            STATIC_CACHE[key] = (body, gzip.compress(body, 6))
        else:
            STATIC_CACHE[key] = (body, None)
        entry = STATIC_CACHE[key]
    raw, gz = entry
    if gz and accept_gzip:
        hdr['Content-Encoding'] = 'gzip'
        return 200, gz, ctype, hdr
    return 200, raw, ctype, hdr


REASONS = {200: 'OK', 204: 'No Content', 400: 'Bad Request', 401: 'Unauthorized',
           403: 'Forbidden', 404: 'Not Found', 405: 'Method Not Allowed',
           408: 'Request Timeout', 413: 'Payload Too Large', 429: 'Too Many Requests',
           500: 'Internal Server Error'}


async def http_reply(writer, code, body, ctype, hdr, head=False):
    lines = ['HTTP/1.1 %d %s' % (code, REASONS.get(code, 'OK')),
             'Content-Type: ' + ctype, 'Content-Length: %d' % len(body),
             'Connection: close', 'X-Content-Type-Options: ' + 'nosniff',
             'X-Frame-Options: SAMEORIGIN', 'Referrer-Policy: no-referrer']
    lines += ['%s: %s' % kv for kv in hdr.items()]
    writer.write(('\r\n'.join(lines) + '\r\n\r\n').encode() + (b'' if head else body))
    await writer.drain()


def cors_headers():
    return {'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Key',
            'Access-Control-Allow-Methods': 'POST, GET, OPTIONS'}


# ------------------------------------------------------------------ админ-API
def admin_ok(hdrs):
    key = CFG['admin_key']
    if not key:
        return False
    return safe_eq(str(hdrs.get('x-admin-key', '')), key)


def safe_eq(a, b):
    """compare_digest, не падающий на не-ASCII вводе."""
    try:
        return bool(a) and hmac.compare_digest(a.encode('utf-8'), b.encode('utf-8'))
    except Exception:  # noqa
        return False


def admin_state():
    """Синхронная сборка без await внутри; вызывается под STORE.lock, все итерации — по копиям."""
    return {
        'ok': True,
        'uptime': int(time.time() - START_T),
        'conns': len(CONNS),
        'restart_in': restart_left(),
        'rooms': [r.summary() for r in ROOMS.values()],
        'players': [
            {'id': q.id, 'n': q.name, 'ip': q.ip, 'acc': q.account_id,
             'room': (q.room.mode if q.room else None), 'alive': q.alive,
             'k': q.kills, 'd': q.deaths, 'score': q.score}
            for q in [c.player for c in list(CONNS) if c.player is not None]
        ],
        'accounts': [
            {'id': a['id'], 'login': a['login'], 'name': a['name'],
             'created': int(a.get('created', 0)),
             'crystals': int(a.get('crystals', 0)),
             'muted': bool(STORE.acc_muted(a)),
             'muted_until': a.get('muted_until'),
             'warns': warn_count(a),
             'games': a['stats'].get('games', 0), 'wins': a['stats'].get('wins', 0),
             'kills': a['stats'].get('kills', 0), 'banned': bool(STORE.acc_banned(a))}
            for a in list(STORE.accounts.values())
        ],
        'bans': copy.deepcopy(STORE.bans),
        'news': copy.deepcopy(STORE.news),
        'banwords': Store._mod_words(),
        'rules': copy.deepcopy(STORE.rules),
        'modset': dict(STORE.modset),
        'chatlog': STORE.chatlog[-150:],
        'modlog': STORE.modlog[-100:],
    }


async def admin_api(writer, method, path, hdrs, body, ip=''):
    # перебор ключа: после 5 неудач за 5 минут IP отрезается от админ-API на 10 минут
    if ip and admin_blocked(ip):
        await http_json(writer, 429, {'ok': False, 'err': 'Слишком много попыток. Подождите 10 минут.'})
        return
    if not admin_ok(hdrs):
        if ip:
            admin_fail(ip)
        await http_json(writer, 403, {'ok': False, 'err': 'Неверный админ-ключ'})
        return
    if ip:
        admin_ok_ip(ip)
    action = path[len('/api/admin/'):].strip('/')
    try:
        m = json.loads(body.decode('utf-8')) if (method == 'POST' and body) else {}
    except Exception:
        m = {}
    if not isinstance(m, dict):
        m = {}
    if method == 'GET' and action == 'state':
        async with STORE.lock:
            st = admin_state()
        await http_json(writer, 200, st, {'Cache-Control': 'no-store'})
        return
    if method != 'POST':
        await http_json(writer, 405, {'ok': False, 'err': 'method'})
        return
    if action == 'kick':
        pid = int(num(m.get('id'), -1))
        target = None
        for c in list(CONNS):
            if c.player is not None and c.player.id == pid:
                target = c
                break
        if not target:
            await http_json(writer, 404, {'ok': False, 'err': 'Игрок не найден'})
            return
        q = target.player
        log.info('admin: kick %s (#%d)', q.name, q.id)
        q.send({'t': 'kicked', 'r': 'Отключён администратором'})
        if q.room:
            q.room.remove(q)
        target.close()
        await http_json(writer, 200, {'ok': True, 'r': 'Кикнут: ' + q.name})
        return
    if action == 'broadcast':
        text = re.sub(r'\s+', ' ', str(m.get('text', ''))).strip()[:120]
        if not text:
            await http_json(writer, 400, {'ok': False, 'err': 'Пустой текст'})
            return
        msg = {'t': 'chat', 'id': 0, 'n': 'АДМИН', 'tm': 0, 'c': 'all', 'm': text}
        frame = make_frame(json.dumps(msg, ensure_ascii=False, separators=(',', ':')))
        for c in list(CONNS):
            if c.player is not None:
                c.send_frame(frame)
        log.info('admin: broadcast: %s', text)
        await http_json(writer, 200, {'ok': True})
        return
    if action == 'news':
        # редактор новостей: заменяет ленту «Новости» в клиентах и сохраняется в data/news.json
        items = m.get('items')
        if not isinstance(items, list):
            items = []
        clean = []
        for it in items:
            if not isinstance(it, dict):
                continue
            text = re.sub(r'\s+', ' ', str(it.get('text', ''))).strip()[:200]
            if not text:
                continue
            kind = str(it.get('kind', 'info'))
            if kind not in ('info', 'ok', 'bad', 'gift'):
                kind = 'info'
            clean.append({'text': text, 'kind': kind})
        clean = clean[:40]
        async with STORE.lock:
            STORE.news = clean
            STORE.dirty = True
        frame = make_frame(json.dumps({'t': 'news', 'items': clean},
                                      ensure_ascii=False, separators=(',', ':')))
        for c in list(CONNS):
            if c.player is not None:
                c.send_frame(frame)
        log.info('admin: news updated (%d)', len(clean))
        await http_json(writer, 200, {'ok': True, 'items': clean})
        return
    if action == 'mute':
        aid = int(num(m.get('aid'), 0))
        minutes = float(num(m.get('minutes'), 10))
        reason = str(m.get('reason', ''))[:80]
        async with STORE.lock:
            acc = STORE.by_id.get(aid)
            if acc is None:
                await http_json(writer, 404, {'ok': False, 'err': 'Нет аккаунта'})
                return
            acc['muted_until'] = 0 if minutes <= 0 else time.time() + minutes * 60
            STORE.dirty = True
        log.info('admin: mute acc#%d minutes=%s (%s)', aid, minutes, reason)
        for c in list(CONNS):
            q = c.player
            if q is not None and q.account_id == aid:
                q.send({'t': 'chat', 'id': 0, 'n': 'СИСТЕМА', 'tm': 0, 'c': 'all',
                        'm': 'Администратор выдал мут чата' + (': ' + reason if reason else '')})
        await http_json(writer, 200, {'ok': True})
        return
    if action == 'unmute':
        aid = int(num(m.get('aid'), 0))
        async with STORE.lock:
            acc = STORE.by_id.get(aid)
            if acc is not None:
                acc['muted_until'] = None
                STORE.dirty = True
        log.info('admin: unmute acc#%d', aid)
        await http_json(writer, 200, {'ok': True})
        return
    if action == 'crystals':
        aid = int(num(m.get('aid'), 0))
        amount = int(clamp(num(m.get('amount'), 0), -10000000, 10000000))
        async with STORE.lock:
            acc = STORE.by_id.get(aid)
            if acc is None:
                await http_json(writer, 404, {'ok': False, 'err': 'Нет аккаунта'})
                return
            acc['crystals'] = max(0, int(acc.get('crystals', 0)) + amount)
            STORE.dirty = True
        log.info('admin: crystals acc#%d %+d', aid, amount)
        for c in list(CONNS):
            q = c.player
            if q is not None and q.account_id == aid:
                q.send({'t': 'crystals', 'd': amount})
        await http_json(writer, 200, {'ok': True, 'crystals': acc['crystals']})
        return
    if action == 'rename':
        aid = int(num(m.get('aid'), 0))
        name = clean_name(m.get('name'))
        if STORE.modset.get('name_check', True) and not name_allowed(name):
            await http_json(writer, 400, {'ok': False, 'err': 'Имя содержит запрещённые слова'})
            return
        async with STORE.lock:
            acc = STORE.by_id.get(aid)
            if acc is None:
                await http_json(writer, 404, {'ok': False, 'err': 'Нет аккаунта'})
                return
            acc['name'] = name
            STORE.dirty = True
        log.info('admin: rename acc#%d -> %s', aid, name)
        for c in list(CONNS):
            q = c.player
            if q is not None and q.account_id == aid:
                q.name = name
                q.send({'t': 'renamed', 'name': name})
        await http_json(writer, 200, {'ok': True, 'name': name})
        return
    if action == 'ban':
        ip = str(m.get('ip', '')).strip()
        aid = int(num(m.get('aid'), 0))
        hours = float(num(m.get('hours'), 24))
        reason = str(m.get('reason', ''))[:80]
        if not ip and not aid:
            await http_json(writer, 400, {'ok': False, 'err': 'Нужен ip или aid'})
            return
        await STORE.ban(ip=ip or None, aid=aid or None, hours=hours, reason=reason)
        log.info('admin: ban ip=%s aid=%s hours=%s (%s)', ip, aid, hours, reason)
        for c in list(CONNS):  # выкинуть забаненных онлайн
            q = c.player
            if q is not None and ((ip and q.ip == ip) or (aid and q.account_id == aid)):
                q.send({'t': 'kicked', 'r': 'Аккаунт заблокирован администратором'})
                if q.room:
                    q.room.remove(q)
                c.close()
        await http_json(writer, 200, {'ok': True})
        return
    if action == 'unban':
        ip = str(m.get('ip', '')).strip()
        aid = int(num(m.get('aid'), 0))
        async with STORE.lock:
            if ip:
                STORE.bans['ip'].pop(ip, None)
            if aid:
                STORE.bans['acc'].pop(str(aid), None)
                acc = STORE.by_id.get(aid)
                if acc is not None and acc.get('banned'):
                    acc['banned'] = None
            STORE.dirty = True
        log.info('admin: unban ip=%s aid=%s', ip, aid)
        await http_json(writer, 200, {'ok': True})
        return
    if action == 'delacc':
        aid = int(num(m.get('aid'), 0))
        async with STORE.lock:
            acc = STORE.by_id.get(aid)
            if acc:
                login = acc['login']
                STORE.accounts.pop(login.lower(), None)
                STORE.by_id.pop(aid, None)
                STORE.sessions = {tk: s for tk, s in list(STORE.sessions.items()) if s.get('aid') != aid}
                STORE.dirty = True
        if not acc:
            await http_json(writer, 404, {'ok': False, 'err': 'Нет аккаунта'})
            return
        for c in list(CONNS):
            q = c.player
            if q is not None and q.account_id == aid:
                q.send({'t': 'kicked', 'r': 'Аккаунт удалён администратором'})
                if q.room:
                    q.room.remove(q)
                c.close()
        log.info('admin: delacc %s (#%d)', login, aid)
        await http_json(writer, 200, {'ok': True, 'r': 'Удалён ' + login})
        return
    if action == 'restart':
        if m.get('cancel'):
            schedule_restart(None)
            log.info('admin: restart cancelled (плановый срок восстановлен)')
        else:
            delay = clamp(num(m.get('delay'), 30), 0, 3600)
            schedule_restart(delay)
            log.info('admin: restart in %ds', delay)
        await http_json(writer, 200, {'ok': True, 'restart_in': restart_left()})
        return
    if action == 'save':
        await STORE.save(force=True)
        log.info('admin: save')
        await http_json(writer, 200, {'ok': True})
        return
    # ------------------------------------------------------------------ модерация чата
    if action == 'warn':
        aid = int(num(m.get('aid'), 0))
        reason = str(m.get('reason', '')).strip()[:120] or 'Нарушение правил'
        target = None
        for c in list(CONNS):
            if c.player is not None and c.player.account_id == aid:
                target = c.player
                break
        acc = STORE.by_id.get(aid)
        if acc is None:
            await http_json(writer, 404, {'ok': False, 'err': 'Нет аккаунта'})
            return
        if target is not None:
            note_warn(target, reason, 'admin')
        else:
            acc.setdefault('warns', []).append(time.time())
            STORE.dirty = True
            modlog_add('admin', 'warn', acc.get('name', aid), reason + ' (офлайн)')
        await http_json(writer, 200, {'ok': True, 'warns': warn_count(acc)})
        return
    if action == 'clearwarns':
        aid = int(num(m.get('aid'), 0))
        async with STORE.lock:
            acc = STORE.by_id.get(aid)
            if acc is None:
                await http_json(writer, 404, {'ok': False, 'err': 'Нет аккаунта'})
                return
            acc['warns'] = []
            STORE.dirty = True
        modlog_add('admin', 'clearwarns', acc.get('name', aid))
        await http_json(writer, 200, {'ok': True})
        return
    if action == 'pm':
        pid = int(num(m.get('id'), 0))
        text = re.sub(r'\s+', ' ', str(m.get('text', ''))).strip()[:160]
        if not text:
            await http_json(writer, 400, {'ok': False, 'err': 'Пустой текст'})
            return
        for c in list(CONNS):
            q = c.player
            if q is not None and q.id == pid:
                sys_chat(q, '💌 Админ: ' + text)
                log.info('admin: pm -> %s: %s', q.name, text)
                await http_json(writer, 200, {'ok': True})
                return
        await http_json(writer, 404, {'ok': False, 'err': 'Игрок не найден'})
        return
    if action == 'kill':
        pid = int(num(m.get('id'), 0))
        for c in list(CONNS):
            q = c.player
            if q is not None and q.id == pid and q.room is not None:
                q.room.damage(q, 1e9, killer=None)
                modlog_add('admin', 'kill', q.name, 'убит админом')
                await http_json(writer, 200, {'ok': True})
                return
        await http_json(writer, 404, {'ok': False, 'err': 'Игрок не в бою'})
        return
    if action == 'move':
        pid = int(num(m.get('id'), 0))
        dest = str(m.get('room', '')).strip()
        for c in list(CONNS):
            q = c.player
            if q is not None and q.id == pid:
                if q.room is not None:
                    q.room.remove(q)
                if dest and dest in ROOMS:
                    room = ROOMS[dest]
                    ok, res = room.try_add(q, -1)
                    if ok:
                        q.room_t = now()
                        room.add(q, res)
                        await http_json(writer, 200, {'ok': True, 'r': 'Перемещён в ' + dest})
                        return
                    await http_json(writer, 400, {'ok': False, 'err': res})
                    return
                await http_json(writer, 200, {'ok': True, 'r': 'Отправлен в лобби'})
                return
        await http_json(writer, 404, {'ok': False, 'err': 'Игрок не найден'})
        return
    if action == 'roomclose':
        room = ROOMS.get(str(m.get('room', '')))
        if room is None:
            await http_json(writer, 404, {'ok': False, 'err': 'Нет комнаты'})
            return
        for q in list(room.players.values()):
            q.send({'t': 'kicked', 'r': 'Комната закрыта администратором'})
            room.remove(q)
        modlog_add('admin', 'roomclose', room.mode)
        await http_json(writer, 200, {'ok': True})
        return
    if action == 'banwords_add':
        word = str(m.get('word', '')).strip().lower()[:60]
        act = str(m.get('action', 'block'))
        if act not in MOD_ACTIONS:
            act = 'block'
        if not word:
            await http_json(writer, 400, {'ok': False, 'err': 'Пустое слово'})
            return
        async with STORE.lock:
            for w in STORE.banwords:
                if w['w'].lower() == word:
                    w['a'] = act
                    STORE.dirty = True
                    await http_json(writer, 200, {'ok': True, 'updated': True})
                    return
            STORE.banwords.append({'w': word, 'a': act, 'pin': False})
            STORE.dirty = True
        modlog_add('admin', 'banword+', word, act)
        await http_json(writer, 200, {'ok': True})
        return
    if action == 'banwords_remove':
        word = str(m.get('word', '')).strip().lower()[:60]
        async with STORE.lock:
            for w in list(STORE.banwords):
                if w['w'].lower() == word:
                    if w.get('pin'):
                        await http_json(writer, 400, {'ok': False, 'err': 'Слово закреплено — удалить нельзя'})
                        return
                    STORE.banwords.remove(w)
                    STORE.dirty = True
                    modlog_add('admin', 'banword-', word)
                    await http_json(writer, 200, {'ok': True})
                    return
        await http_json(writer, 404, {'ok': False, 'err': 'Слова нет в списке'})
        return
    if action == 'banwords_test':
        text = str(m.get('text', ''))[:300]
        hits = [{'w': h['w'], 'a': h.get('a', 'block')} for h in check_text(text)]
        await http_json(writer, 200, {'ok': True, 'hits': hits})
        return
    if action == 'rules':
        items = m.get('items')
        if not isinstance(items, list):
            items = []
        clean = []
        for it in items:
            if not isinstance(it, dict):
                continue
            text = re.sub(r'\s+', ' ', str(it.get('text', ''))).strip()[:300]
            if not text:
                continue
            clean.append({'text': text, 'p': str(it.get('p', ''))[:40]})
        clean = clean[:60]
        async with STORE.lock:
            STORE.rules = clean
            STORE.dirty = True
        frame = make_frame(json.dumps({'t': 'rules', 'items': clean},
                                      ensure_ascii=False, separators=(',', ':')))
        for c in list(CONNS):
            if c.player is not None:
                c.send_frame(frame)
        modlog_add('admin', 'rules', 'обновлены (%d)' % len(clean))
        await http_json(writer, 200, {'ok': True, 'items': clean})
        return
    if action == 'modset':
        key = str(m.get('key', ''))
        if key not in MODSET_DEF:
            await http_json(writer, 400, {'ok': False, 'err': 'Нет такой настройки'})
            return
        if isinstance(MODSET_DEF[key], bool):
            val = str(m.get('value')).strip().lower() in ('1', 'true', 'yes', 'on', 'да', 'вкл')
        else:
            try:
                val = type(MODSET_DEF[key])(m.get('value'))
            except (TypeError, ValueError):
                await http_json(writer, 400, {'ok': False, 'err': 'Неверное значение'})
                return
        STORE.modset[key] = val
        STORE.dirty = True
        modlog_add('admin', 'modset', key, str(val))
        await http_json(writer, 200, {'ok': True, 'modset': dict(STORE.modset)})
        return
    if action == 'chatlog_clear':
        STORE.chatlog = []
        STORE.dirty = True
        await http_json(writer, 200, {'ok': True})
        return
    if action == 'modlog_clear':
        STORE.modlog = []
        STORE.dirty = True
        await http_json(writer, 200, {'ok': True})
        return
    await http_json(writer, 404, {'ok': False, 'err': 'Нет такого действия'})


async def http_json(writer, code, obj, extra=None):
    hdr = cors_headers()
    hdr.update(extra or {})
    await http_reply(writer, code, json.dumps(obj, ensure_ascii=False).encode(),
                     'application/json; charset=utf-8', hdr)


async def read_http_body(reader, hdrs, limit=8192):
    try:
        n = int(hdrs.get('content-length', '0'))
    except ValueError:
        return None
    if n <= 0 or n > limit:
        return None
    try:
        return await asyncio.wait_for(reader.readexactly(n), 10)
    except Exception:
        return None


ip_count = {}


async def client_connected(reader, writer):
    peer = writer.get_extra_info('peername')
    peer_ip = peer[0] if peer else '?'
    try:
        req = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 10)
    except Exception:
        writer.close()
        return
    try:
        head = req.decode('latin1').split('\r\n')
        method, path, _ = head[0].split(' ', 2)
        hdrs = {}
        for ln in head[1:]:
            if ':' in ln:
                k, v = ln.split(':', 1)
                hdrs[k.strip().lower()] = v.strip()
    except Exception:
        writer.close()
        return
    # реальный IP: X-Forwarded-For учитываем ТОЛЬКО за прокси (Koyeb: TRUST_PROXY=1).
    # Берём ПОСЛЕДНИЙ элемент: прокси дописывает реальный IP клиента в конец,
    # а всё, что слева, клиент мог подделать сам (иначе обход банов/лимитов).
    ip = peer_ip
    if CFG['trust_proxy']:
        fwd = [q.strip() for q in hdrs.get('x-forwarded-for', '').split(',') if q.strip()]
        if fwd:
            ip = fwd[-1]
    try:
        # админ-API доступен даже с забаненного IP: иначе, забанив свой адрес
        # (или адрес прокси), админ навсегда терял возможность разбанить
        if path.startswith('/api/admin/'):
            if hdrs.get('upgrade', '').lower() == 'websocket':
                await ws_session(reader, writer, hdrs, ip)
                return
            body = await read_http_body(reader, hdrs) if method == 'POST' else b''
            if method == 'POST' and body is None:
                body = b''
            await admin_api(writer, method, path, hdrs, body or b'', ip)
            return
        if STORE is not None and STORE.ip_banned(ip):
            # забаненным отдаём только страницу блокировки и информацию о бане —
            # ни игру, ни статику, ни API. Вместо голого «banned» — бархатная
            # страница с причиной и сроком, что бы ни открыл игрок.
            entry = path.split('?', 1)[0].rstrip('/').lstrip('/')
            if method == 'GET' and (entry in ('', 'banned', 'index.html', 'game.html') or entry.startswith('banned')):
                code, body, ctype, h = static_response(
                    '/banned.html', 'gzip' in hdrs.get('accept-encoding', ''), method == 'HEAD')
                await http_reply(writer, code, body, ctype, h, method == 'HEAD')
                return
            if method == 'POST' and path.rstrip('/') in ('/api/baninfo', '/api/baninfo/'):
                body = await read_http_body(reader, hdrs) or b''
                code, obj = await api_baninfo(ip, body)
                await http_json(writer, code, obj, {'Cache-Control': 'no-store'})
                return
            await http_reply(writer, 403, b'banned', 'text/plain', {})
            return
        if hdrs.get('upgrade', '').lower() == 'websocket':
            await ws_session(reader, writer, hdrs, ip)
            return
        if method == 'OPTIONS':
            await http_reply(writer, 204, b'', 'text/plain', cors_headers())
            return
        if method == 'POST' and path == '/api/register':
            body = await read_http_body(reader, hdrs)
            if body is None:
                await http_json(writer, 400, {'ok': False, 'err': 'Пустое тело запроса'})
                return
            code, obj = await api_register(ip, body)
            await http_json(writer, code, obj)
            return
        if method == 'POST' and path == '/api/login':
            body = await read_http_body(reader, hdrs)
            if body is None:
                await http_json(writer, 400, {'ok': False, 'err': 'Пустое тело запроса'})
                return
            code, obj = await api_login(ip, body)
            await http_json(writer, code, obj)
            return
        if method == 'GET' and path.rstrip('/') in ('/api/rooms', '/api/rooms/'):
            await http_json(writer, 200, [r.summary() for r in ROOMS.values()],
                            {'Cache-Control': 'no-store'})
        elif method == 'GET' and path.rstrip('/') in ('/api/news', '/api/news/'):
            async with STORE.lock:
                items = copy.deepcopy(STORE.news)
            await http_json(writer, 200, {'ok': True, 'items': items},
                            {'Cache-Control': 'no-store'})
        elif method == 'GET' and path.rstrip('/') in ('/api/rules', '/api/rules/'):
            async with STORE.lock:
                items = copy.deepcopy(STORE.rules)
            await http_json(writer, 200, {'ok': True, 'items': items},
                            {'Cache-Control': 'no-store'})
        elif method == 'GET' and path.rstrip('/') in ('/banned', '/banned/'):
            code, body, ctype, h = static_response(
                '/banned.html', 'gzip' in hdrs.get('accept-encoding', ''), method == 'HEAD')
            await http_reply(writer, code, body, ctype, h, method == 'HEAD')
        elif method == 'POST' and path.rstrip('/') in ('/api/baninfo', '/api/baninfo/'):
            body = await read_http_body(reader, hdrs) or b''
            code, obj = await api_baninfo(ip, body)
            await http_json(writer, code, obj, {'Cache-Control': 'no-store'})
        elif method == 'POST' and path.rstrip('/') in ('/api/delete_account', '/api/delete_account/'):
            body = await read_http_body(reader, hdrs) or b''
            code, obj = await api_delete_account(ip, body)
            await http_json(writer, code, obj, {'Cache-Control': 'no-store'})
        elif method == 'POST' and path == '/api/logout':
            body = await read_http_body(reader, hdrs) or b'{}'
            try:
                m = json.loads(body.decode('utf-8'))
            except Exception:
                m = {}
            token = m.get('token') if isinstance(m, dict) else None
            removed = STORE.logout(token if isinstance(token, str) else None)
            await http_json(writer, 200, {'ok': True, 'removed': bool(removed)})
        elif path.startswith('/health'):
            await http_reply(writer, 200, b'ok', 'text/plain', {})
        elif method in ('GET', 'HEAD'):
            code, body, ctype, h = static_response(path, 'gzip' in hdrs.get('accept-encoding', ''),
                                                   method == 'HEAD')
            await http_reply(writer, code, body, ctype, h, method == 'HEAD')
        else:
            await http_reply(writer, 405, b'method not allowed', 'text/plain', {})
    except Exception as e:  # noqa
        log.exception('http error')
    finally:
        try:
            writer.close()
        except Exception:
            pass


# ------------------------------------------------------------------ WebSocket-сессия
async def ws_pinger(conn):
    try:
        while not conn.closed:
            await asyncio.sleep(WS_PING_INTERVAL)
            if conn.closed:
                break
            conn.send_frame(struct.pack('!BB', 0x89, 0))
    except Exception:
        pass


async def ws_session(reader, writer, hdrs, ip):
    origin = hdrs.get('origin')
    allowed = CFG.get('allowed_origins') or []
    if allowed and origin and origin not in allowed:
        await http_reply(writer, 403, b'origin', 'text/plain', {})
        return
    if hdrs.get('sec-websocket-version', '').strip() != '13':
        await http_reply(writer, 400, b'unsupported ws version', 'text/plain', {})
        return
    if ip_count.get(ip, 0) >= CFG['max_conn_per_ip']:
        await http_reply(writer, 403, b'too many connections', 'text/plain', {})
        return
    key = hdrs.get('sec-websocket-key')
    if not key:
        await http_reply(writer, 400, b'no key', 'text/plain', {})
        return
    acc = base64.b64encode(hashlib.sha1(key.encode() + GUID).digest()).decode()
    writer.write(('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
                  'Sec-WebSocket-Accept: %s\r\n\r\n' % acc).encode())
    await writer.drain()
    ip_count[ip] = ip_count.get(ip, 0) + 1
    conn = Conn(reader, writer, ip)
    CONNS.add(conn)
    player = Player(conn)
    conn.player = player
    ping_task = asyncio.create_task(ws_pinger(conn))
    buf = b''
    try:
        while not conn.closed:
            fin, op, data = await asyncio.wait_for(read_frame(reader), WS_READ_TIMEOUT)
            if op == 0x8:
                break
            if op == 0x9:  # ping -> pong (payload не длиннее 125)
                if len(data) <= 125:
                    conn.send_frame(struct.pack('!BB', 0x8A, len(data)) + data)
                continue
            if op == 0xA:
                continue
            if op in (0x1, 0x0):
                buf += data
                if len(buf) > MAX_FRAME:
                    break
                if not fin:
                    continue
                text, buf = buf, b''
                tn = now()
                if tn - conn.win_t >= 1:
                    conn.win_t, conn.win_n = tn, 0
                conn.win_n += 1
                if conn.win_n > CFG['max_msg_per_sec']:
                    log.warning('flood from %s', ip)
                    break
                try:
                    msg = json.loads(text.decode('utf-8'))
                    if isinstance(msg, dict):
                        await handle(player, msg)
                except (ValueError, UnicodeDecodeError):
                    pass
                except Exception:
                    log.exception('handler error')
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, ValueError):
        pass
    finally:
        ping_task.cancel()
        if player.room:
            player.room.remove(player)
        CONNS.discard(conn)
        _last_chat.pop(player.id, None)
        ip_count[ip] = max(0, ip_count.get(ip, 1) - 1)
        conn.close()


# ------------------------------------------------------------------ плановый перезапуск
RESTART = {'at': None, 'sent': set(), 'go': False}   # at — момент перезапуска (monotonic)
RESTART_WARN = (600, 300, 120, 60, 30, 10, 5)         # за сколько секунд предупреждать


def schedule_restart(delay=None):
    """delay=None — плановый срок (restart_hours от старта процесса, 0 = без перезапуска);
    число — перезапуск через delay секунд (админ)."""
    RESTART['sent'] = set()
    if delay is None:
        hrs = num(CFG.get('restart_hours'), 0.0)
        RESTART['at'] = (START_MONO + hrs * 3600.0) if hrs > 0 else None
    else:
        RESTART['at'] = now() + max(0.0, float(delay))


def restart_left():
    if RESTART['at'] is None:
        return None
    return max(0, int(RESTART['at'] - now()))


def fmt_left(sec):
    if sec >= 120:
        return '%d мин' % round(sec / 60.0)
    if sec >= 60:
        return '1 мин'
    return '%d сек' % sec


def announce_restart(left):
    txt = 'Перезапуск сервера через %s. Игра переподключится автоматически.' % fmt_left(left)
    chat = make_frame(json.dumps({'t': 'chat', 'id': 0, 'n': 'АДМИН', 'tm': 0, 'c': 'all', 'm': txt},
                                 ensure_ascii=False, separators=(',', ':')))
    note = make_frame(json.dumps({'t': 'restart', 'in': left}, separators=(',', ':')))
    for c in list(CONNS):
        if c.player is not None:
            c.send_frame(chat)
            c.send_frame(note)
    log.info('restart: предупреждение, осталось %ds', left)


async def restart_scheduler(stop):
    schedule_restart(None)
    while not stop.is_set():
        await asyncio.sleep(1.0)
        left = restart_left()
        if left is None:
            continue
        if left <= 0:
            log.info('restart: пора, останавливаюсь')
            RESTART['go'] = True
            stop.set()
            return
        due = [s for s in RESTART_WARN if left <= s and s not in RESTART['sent']]
        if due:
            RESTART['sent'].update(due)     # при коротком таймере не спамим всеми ступенями сразу
            announce_restart(left)


_save_task = None


async def _safe_save():
    try:
        await STORE.save()
    except Exception:
        log.exception('periodic save failed')


# ------------------------------------------------------------------ игровой цикл
async def game_loop():
    last = now()
    nxt = last
    lobby_t = 0.0
    save_t = 0.0
    while True:
        nxt += TICK
        await asyncio.sleep(max(0.0, nxt - now()))
        t = now()
        dt = min(0.1, t - last)
        last = t
        for r in ROOMS.values():
            try:
                r.tick(dt)
                r._err_n = 0          # успех сбрасывает серию — считаем именно ПОДРЯД
            except Exception:
                r._err_n = getattr(r, '_err_n', 0) + 1
                if r._err_n <= 3 or r._err_n % 100 == 0:
                    log.exception('room %s tick failed (x%d)', r.mode, r._err_n)
                if r._err_n >= 50:
                    # комната стабильно сломана — мягкий перезапуск матча вместо вечных ошибок
                    log.error('room %s: %d ошибок подряд, перезапуск матча', r.mode, r._err_n)
                    try:
                        r.start_match()
                    except Exception:
                        log.exception('room %s restart failed', r.mode)
                    r._err_n = 0
        lobby_t += dt
        if lobby_t >= 2:
            lobby_t = 0
            frame = make_frame(json.dumps({'t': 'rooms', 'rooms': [r.summary() for r in ROOMS.values()]},
                                          ensure_ascii=False, separators=(',', ':')))
            for c in list(CONNS):
                if c.player and c.player.room is None:
                    c.send_frame(frame)
            # гигиена памяти: ip_count и _last_chat иначе растут вечно
            for k in [k for k, v in ip_count.items() if v <= 0]:
                ip_count.pop(k, None)
            if len(_last_chat) > 256:
                live_ids = {c.player.id for c in CONNS if c.player}
                for k in [k for k in _last_chat if k not in live_ids]:
                    _last_chat.pop(k, None)
                for k in [k for k in _chat_times if k not in live_ids]:
                    _chat_times.pop(k, None)
        save_t += dt
        if save_t >= SAVE_INTERVAL:
            save_t = 0
            # в фоне: deepcopy + запись на диск не должны подвешивать тики 20 Гц
            global _save_task
            if _save_task is None or _save_task.done():
                _save_task = spawn(_safe_save())
        if nxt < t - 1:
            nxt = t


async def main():
    global STORE
    load_cfg()
    key = CFG.get('admin_key', '')
    if not key:
        log.warning('ADMIN_KEY не задан — админ-панель и админ-API ЗАКРЫТЫ '
                    '(на Amvera задайте его в «Настройки → Переменные окружения»)')
    elif len(key) < 10:
        log.warning('ADMIN_KEY короче 10 символов — подберите длинный случайный ключ')
    data_dir = Path(CFG['data_dir'])
    if not data_dir.is_absolute():
        data_dir = BASE / data_dir
    STORE = Store(data_dir)
    await STORE.load()
    for m in MODES:
        ROOMS[m] = Room(m)
    srv = await asyncio.start_server(client_connected, CFG['host'], CFG['port'],
                                     limit=2 ** 16, backlog=256)
    log.info('TANKI server: http://%s:%d  (комнаты: %s)', CFG['host'], CFG['port'], ', '.join(ROOMS))
    log.info('static: %s   data: %s', (BASE / CFG['static_dir']).resolve(), data_dir.resolve())
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    have_sig = False
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop.set)
            have_sig = True
        except NotImplementedError:
            pass
    if not have_sig:
        # Windows: add_signal_handler недоступен — fallback через signal.signal,
        # иначе Ctrl+C завершал процесс БЕЗ сохранения данных.
        # SIGBREAK (Ctrl+Break) — единственный сигнал, доставляемый в
        # процессную группу; CTRL_C_EVENT в группу не доходит.
        def _win_stop(signum, frame):
            loop.call_soon_threadsafe(stop.set)
        try:
            signal.signal(signal.SIGINT, _win_stop)
            signal.signal(signal.SIGTERM, _win_stop)
            if hasattr(signal, 'SIGBREAK'):
                signal.signal(signal.SIGBREAK, _win_stop)
        except (ValueError, OSError):  # не главный поток — сигнал ставить нельзя
            pass
    game_task = asyncio.create_task(game_loop())
    sched_task = asyncio.create_task(restart_scheduler(stop))
    await stop.wait()
    restart = RESTART['go']
    log.info('%s: сохраняю данные...', 'restart' if restart else 'shutdown')
    srv.close()                                   # новые подключения больше не принимаем
    game_task.cancel()
    sched_task.cancel()
    await asyncio.gather(game_task, sched_task, return_exceptions=True)
    # ВАЖНО: сначала закрываем клиентов и сохраняем данные, и только потом ждём сервер.
    # В Python 3.12 Server.wait_closed() ждёт ЗАКРЫТИЯ ВСЕХ соединений — раньше при живых
    # WebSocket остановка зависала, а хостинг убивал процесс (SIGKILL) до сохранения data/.
    for c in list(CONNS):
        try:
            if c.player is not None:
                c.send({'t': 'restart', 'in': 0})  # клиент покажет «перезапуск» и переподключится
            c.close()
        except Exception:
            pass
    if _BG_TASKS:                                  # дождаться начисления статистики/банов
        await asyncio.wait(list(_BG_TASKS), timeout=2.0)
    try:
        await STORE.save(force=True)
    except Exception:
        log.exception('final save failed')
    await asyncio.sleep(0.3)                       # дать транспортам дописать close-кадры
    try:
        await asyncio.wait_for(srv.wait_closed(), 2.0)
    except Exception:  # noqa
        pass
    log.info('bye')
    return restart


def reexec():
    """Перезапуск процесса на месте: тот же PID/контейнер, порт освобождается и занимается заново,
    data/ остаётся на диске. Если exec невозможен — выходим с кодом 3 (супервизор поднимет заново)."""
    log.info('restart: перезапуск процесса')
    logging.shutdown()
    try:
        os.execv(sys.executable, [sys.executable, os.path.abspath(sys.argv[0])] + sys.argv[1:])
    except Exception:
        logging.basicConfig(level=logging.INFO)
        log.exception('execv failed')
        sys.exit(3)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    need_restart = False
    try:
        need_restart = bool(asyncio.run(main()))
    except KeyboardInterrupt:
        pass
    if need_restart:
        reexec()
