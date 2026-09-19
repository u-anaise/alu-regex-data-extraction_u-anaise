import re
import json
import os

domains={ "general": re.compile(r'@alueducation\.com'),
          "si": re.compile(r'@si\.alueducation\.com'),
          "alumni": re.compile(r'@alumni\.alueducation\.com'),
}

EMAIL_RE=re.compile(r"[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}")
# print(re.match(EMAIL_RE, "gei@gmail.com"))

URL_RE=re.compile(r'\bhttps?://[^\s<>"\'\)]+|\bwww\.[^\s<>"\'\)]+')
# print(re.match(URL_RE, "http:/jkds"))

PHONE_RE=re.compile(r"(07\d{8}|\+2507\d{8})")
# print(re.fullmatch(PHONE_RE, "07800923939"))

CARD_NO_RE=re.compile('\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{0,4}\b')

THREAT_PATTERNS=[
  re.compile(r'<\s*script.*?>', re.IGNORECASE),
  re.compile(r'(--|;)\s*DROP\s+TABLE', re.IGNORECASE),
  re.compile(r"['\"]\s*;\s*--"),
  re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f]'),
]


#Validation

def luhn_check(number: str) -> bool:
  digits= [int(d) for d in number]
  digits.reverse()
  total=0
  for i, d in enumerate(digits):
    if i%2==1:
      d*=2
      if d>9:
        d-=9
    total+=d
  return total%10==0

def flag_threats(line: str) -> list[str]:
  return [p.pattern for p in THREAT_PATTERNS if p.search(line)]

def mask_email(email: str) -> str:
  local, _, domain=email.partition('@')
  visible = local[:2] if len(local) > 2 else local[:1]
  return f"{visible}{'*' * max(len(local) - len(visible), 1)}@{domain}"

def mask_card(card: str) -> str:
  digits = re.sub(r'\D', '', card)
  return f"**** **** **** {digits[-4:]}"
