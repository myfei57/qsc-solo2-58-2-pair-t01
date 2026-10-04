"""Sensitive categories and the built-in classifier catalog.

A category is one detectable shape (email, mainland mobile number, ...). Each
category binds two independent signals:

* column-name hints (strong/weak keyword phrases, matched against tokenized
  names, with Chinese phrase matching on the raw name);
* sample-value hints (a regular expression plus an optional checksum
  validator, and a minimum hit ratio over non-empty samples).

The scanner in :mod:`maskhub.discovery.scanner` combines the two signals; the
catalog here is intentionally pure data so that adding a category never
requires touching the scoring logic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

SENSITIVITY_LEVELS = ("public", "personal", "sensitive", "special")


@dataclass(frozen=True)
class Category:
    identifier: str
    sensitivity: str
    name_strong: tuple[str, ...]
    name_weak: tuple[str, ...]
    pattern: str
    min_ratio: float
    validator: str = ""
    flags: int = 0
    # A loose pattern (names, dates) that routinely matches non-sensitive
    # text is capped at 0.7 on the value channel, so it only auto-confirms
    # together with a supporting column name.
    value_weak: bool = False
    # Column-name phrases that argue *against* this category. When one hits
    # without a positive strong phrase, the value signal is demoted to a
    # weak hint (e.g. a generic ``created_at`` column is not a birthday).
    name_exclude: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.identifier.strip():
            raise ValueError("category identifier is required")
        if self.sensitivity not in SENSITIVITY_LEVELS:
            raise ValueError(f"unknown sensitivity {self.sensitivity!r}")
        if not 0.0 < self.min_ratio <= 1.0:
            raise ValueError("min_ratio must be within (0, 1]")
        re.compile(self.pattern, self.flags)  # fail fast on a bad pattern

    def as_dict(self) -> dict[str, object]:
        return {
            "identifier": self.identifier,
            "sensitivity": self.sensitivity,
            "name_strong": list(self.name_strong),
            "name_weak": list(self.name_weak),
            "min_ratio": self.min_ratio,
            "validator": self.validator,
        }


# ---------------------------------------------------------------------------
# Sample validators
# ---------------------------------------------------------------------------

_CNID_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_CNID_CHECKS = "10X98765432"


def validate_cnid(value: str) -> bool:
    body = value[:17]
    if not body.isdigit():
        return False
    total = sum(int(digit) * weight for digit, weight in zip(body, _CNID_WEIGHTS))
    return _CNID_CHECKS[total % 11] == value[17].upper()


def luhn_ok(value: str) -> bool:
    digits = [int(ch) for ch in value if ch.isdigit()]
    if not digits:
        return False
    checksum = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


VALIDATORS = {
    "cnid_checksum": validate_cnid,
    "luhn": luhn_ok,
}

_IGNORECASE = re.IGNORECASE

BUILTIN_CATEGORIES: tuple[Category, ...] = (
    Category(
        identifier="email",
        sensitivity="personal",
        name_strong=("email", "e_mail", "mail"),
        name_weak=(),
        pattern=r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$",
        min_ratio=0.9,
    ),
    Category(
        identifier="cn_mobile",
        sensitivity="personal",
        name_strong=("mobile", "cellphone", "phone"),
        name_weak=("tel", "contact"),
        pattern=r"^1[3-9]\d{9}$",
        min_ratio=0.9,
    ),
    Category(
        identifier="cn_id_card",
        sensitivity="special",
        name_strong=("idcard", "id_no", "idno", "identity", "身份证"),
        name_weak=("id", "cert", "credential", "证件"),
        pattern=r"^\d{17}[\dXx]$",
        min_ratio=0.9,
        validator="cnid_checksum",
    ),
    Category(
        identifier="bank_card",
        sensitivity="sensitive",
        name_strong=("bankcard", "card_no", "cardno"),
        name_weak=("card", "account_no", "acct_no", "银行卡"),
        pattern=r"^\d[ \d]{12,22}\d$",
        min_ratio=0.9,
        validator="luhn",
    ),
    Category(
        identifier="person_name",
        sensitivity="personal",
        name_strong=("fullname", "username", "realname", "name", "姓名"),
        name_weak=("contact", "owner", "user", "员工", "客户"),
        pattern=r"^[一-龥·]{1,6}(?:[·.][一-龥]{1,8})?$|^[A-Za-z][A-Za-z'’\-]*(?:[ ][A-Za-z][A-Za-z'’\-]*){0,2}$",
        min_ratio=0.95,
        value_weak=True,
    ),
    Category(
        identifier="address",
        sensitivity="personal",
        name_strong=("address", "addr", "地址", "住址"),
        name_weak=("location", "street", "城市"),
        pattern=(
            # must contain an address component marker; bare alphanumeric
            # strings (phone numbers, ids, free text) never qualify
            r"^(?=.*(?:[省市区县镇村路街道号幢栋单元室]|"
            r"street|road|avenue|lane|district|no\.\s?\d))"
            r"[一-龥A-Za-z0-9 ,.\-#]{5,120}$"
        ),
        min_ratio=0.9,
    ),
    Category(
        identifier="license_plate",
        sensitivity="personal",
        name_strong=("plateno", "plate_no", "车牌"),
        name_weak=("vehicle", "车辆"),
        pattern=r"^[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼使领][A-Z][A-Z0-9]{5,6}$",
        min_ratio=0.9,
    ),
    Category(
        identifier="ip_v4",
        sensitivity="public",
        name_strong=("ip", "ipaddr", "ip_address"),
        name_weak=("host", "server"),
        pattern=r"^(?:\d{1,3}\.){3}\d{1,3}$",
        min_ratio=0.9,
    ),
    Category(
        identifier="url",
        sensitivity="public",
        name_strong=("url", "website", "homepage"),
        name_weak=("link", "href"),
        pattern=r"^https?://[^\s]{3,}$",
        min_ratio=0.9,
        flags=_IGNORECASE,
    ),
    Category(
        identifier="uuid",
        sensitivity="public",
        name_strong=("uuid", "guid"),
        name_weak=(),
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        min_ratio=0.95,
        flags=_IGNORECASE,
    ),
    Category(
        identifier="birth_date",
        sensitivity="personal",
        name_strong=("birthday", "birthdate", "birth", "生日", "出生"),
        name_weak=("dob"),
        pattern=(
            r"^\d{4}[-/.]\d{1,2}[-/.]\d{1,2}$"
            r"|^\d{1,2}[-/.]\d{1,2}[-/.]\d{4}$"
            r"|^\d{4}年\d{1,2}月\d{1,2}日$"
        ),
        min_ratio=0.9,
        value_weak=True,
        name_exclude=("created", "updated", "modified", "timestamp", "time", "date",
                      "gmt", "register", "login", "expire", "发布", "创建", "更新", "时间"),
    ),
)


def categories_by_id() -> dict[str, Category]:
    return {category.identifier: category for category in BUILTIN_CATEGORIES}


def ruleset_version(categories: tuple[Category, ...] = BUILTIN_CATEGORIES) -> str:
    """Stable fingerprint of the classifier catalog.

    Bumping a regex, ratio or the validator set changes the version, which is
    what lets a re-scan know previous verdicts were produced by an older
    rule set and must be re-evaluated even when the data shape is unchanged.
    """

    import hashlib

    parts = [
        f"{item.identifier}|{item.sensitivity}|{item.pattern}|{item.flags}|"
        f"{item.min_ratio}|{item.validator}|{','.join(item.name_strong)}|"
        f"{','.join(item.name_weak)}"
        for item in categories
    ]
    digest = hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()
    return f"builtin-{digest[:12]}"
