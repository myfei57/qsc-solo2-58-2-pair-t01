"""Sensitivity detectors combining column-name and sample-shape evidence."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from maskhub.discovery.profile import ColumnProfile


class NameMatch(str, Enum):
    NONE = "none"
    TOKEN = "token"
    STRONG = "strong"


# name_mode describes how name_keywords are applied to a column name.
#   token:  keyword must appear as a snake/camel-case token
#   substring: keyword may appear inside the name (Chinese names)
# pattern_mode describes how sample values are interpreted.
#   regex:   fullmatch against ``pattern``
#   digits:  digits-only value of a fixed length (checksum optional)
#   any:     every non-null value is accepted, shape is the only evidence


@dataclass(frozen=True)
class Detector:
    key: str
    label: str
    sensitivity: str
    name_mode: str
    name_keywords: tuple[str, ...]
    pattern_mode: str = "any"
    pattern: str = ""
    fixed_length: int = 0
    min_length: int = 0
    max_length: int = 0
    min_ratio: float = 0.9
    checksum: bool = False

    def name_match(self, field_name: str) -> NameMatch:
        lowered = field_name.lower()
        tokens = _name_tokens(lowered)
        for keyword in self.name_keywords:
            word = keyword.lower()
            if self.name_mode == "token":
                if word in tokens:
                    return NameMatch.STRONG
            else:  # substring: Chinese keywords or distinctive phrases
                if word in lowered:
                    return NameMatch.STRONG
        return NameMatch.NONE

    def sample_ratio(self, profile: ColumnProfile, values: list[str]) -> float | None:
        if profile.non_null == 0:
            return None
        if self.pattern_mode == "any":
            # Free-text detectors have no shape pattern; a vacuous 100% match
            # must not be presented as sample corroboration.
            return None
        hits = 0
        for raw in values:
            text = raw.strip()
            if not text:
                continue
            if self._matches_value(text):
                hits += 1
        return hits / profile.non_null if profile.non_null else None

    def _matches_value(self, text: str) -> bool:
        if self.pattern_mode == "regex":
            return re.fullmatch(self.pattern, text, flags=re.IGNORECASE) is not None
        if self.pattern_mode == "digits":
            if not text.isdigit():
                return False
            if self.fixed_length and len(text) != self.fixed_length:
                return False
            if self.min_length and len(text) < self.min_length:
                return False
            if self.max_length and len(text) > self.max_length:
                return False
            return (not self.checksum) or _luhn_ok(text)
        return True


def _name_tokens(lowered: str) -> set[str]:
    parts = re.split(r"[^0-9a-zA-Z一-鿿]+", lowered)
    tokens: set[str] = set()
    for part in parts:
        if not part:
            continue
        tokens.add(part)
        # Split camelCase so that "mobilePhone" yields "mobile" and "phone".
        tokens.update(piece.lower() for piece in re.findall(r"[A-Z]?[a-z]+|[A-Z]+", part))
    return tokens


def _luhn_ok(text: str) -> bool:
    total = 0
    for index, ch in enumerate(reversed(text)):
        digit = ord(ch) - ord("0")
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _id_card_checksum(text: str) -> bool:
    if not re.fullmatch(r"\d{17}[\dXx]", text):
        return False
    weights = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
    check_map = "10X98765432"
    total = sum(int(text[i]) * weights[i] for i in range(17))
    return check_map[total % 11] == text[17].upper()


# A dedicated detector because ID cards need an ISO 7064 checksum, not Luhn.
@dataclass(frozen=True)
class IdCardDetector(Detector):
    def __post_init__(self) -> None:
        object.__setattr__(self, "pattern_mode", "regex")
        object.__setattr__(self, "pattern", r"\d{17}[\dXx]")
        object.__setattr__(self, "checksum", True)

    def _matches_value(self, text: str) -> bool:
        return _id_card_checksum(text)


def builtin_detectors() -> tuple[Detector, ...]:
    return (
        Detector(
            key="email",
            label="email address",
            sensitivity="personal",
            name_mode="token",
            name_keywords=("email", "mail", "e_mail"),
            pattern_mode="regex",
            pattern=r"[^@\s]+@[^@\s]+\.[^@\s]{2,}",
        ),
        Detector(
            key="mobile_cn",
            label="mobile phone number (CN)",
            sensitivity="personal",
            name_mode="substring",
            name_keywords=("mobile", "cellphone", "phone", "tel", "手机"),
            pattern_mode="regex",
            pattern=r"1[3-9]\d{9}",
        ),
        IdCardDetector(
            key="id_card_cn",
            label="national identity number (CN)",
            sensitivity="special",
            name_mode="substring",
            name_keywords=("idcard", "id_card", "id_no", "identity", "certno", "身份证", "证件号"),
        ),
        Detector(
            key="bank_card",
            label="bank card number",
            sensitivity="sensitive",
            name_mode="substring",
            name_keywords=("bankcard", "bank_card", "cardno", "card_no", "银行卡", "卡号"),
            pattern_mode="digits",
            min_length=13,
            max_length=19,
            checksum=True,
            min_ratio=0.95,
        ),
        Detector(
            key="passport_cn",
            label="passport number",
            sensitivity="sensitive",
            name_mode="substring",
            name_keywords=("passport", "护照"),
            pattern_mode="regex",
            pattern=r"[EeKkGgDd]\d{8}|[a-zA-Z]\d{8}",
        ),
        Detector(
            key="ipv4",
            label="ipv4 address",
            sensitivity="personal",
            name_mode="token",
            name_keywords=("ip", "ipv4", "ipaddr", "ip_addr"),
            pattern_mode="regex",
            pattern=r"(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}",
        ),
        Detector(
            key="plate_cn",
            label="vehicle license plate (CN)",
            sensitivity="personal",
            name_mode="substring",
            name_keywords=("plate", "车牌"),
            pattern_mode="regex",
            pattern=r"[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼使领][A-Z][A-Z0-9]{5,6}",
        ),
        Detector(
            key="postal_code",
            label="postal code",
            sensitivity="public",
            name_mode="substring",
            name_keywords=("postcode", "postal", "zipcode", "zip", "邮编"),
            pattern_mode="regex",
            pattern=r"\d{6}",
        ),
        Detector(
            key="birth_date",
            label="date of birth",
            sensitivity="personal",
            name_mode="substring",
            name_keywords=("birth", "dob", "出生", "生日"),
            pattern_mode="regex",
            pattern=r"\d{4}[-/.]\d{1,2}[-/.]\d{1,2}|\d{8}",
        ),
        Detector(
            key="person_name",
            label="person name",
            sensitivity="personal",
            name_mode="substring",
            name_keywords=(
                "fullname", "full_name", "firstname", "lastname", "surname",
                "givenname", "realname", "user_name", "username", "姓名", "名字",
            ),
        ),
        Detector(
            key="address",
            label="postal address",
            sensitivity="sensitive",
            name_mode="substring",
            name_keywords=("address", "addr", "住址", "地址"),
        ),
        Detector(
            key="gender",
            label="gender",
            sensitivity="personal",
            name_mode="substring",
            name_keywords=("gender", "sex", "性别"),
            pattern_mode="regex",
            pattern=r"[男女mMfF]|male|female|男|女",
        ),
        Detector(
            key="salary",
            label="salary / income",
            sensitivity="sensitive",
            name_mode="substring",
            name_keywords=("salary", "income", "wage", "工资", "薪资", "收入"),
        ),
        Detector(
            key="password",
            label="password or credential secret",
            sensitivity="special",
            name_mode="token",
            name_keywords=("password", "passwd", "pwd", "secret", "token"),
        ),
    )
