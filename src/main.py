import re
import json

EMAIL_RE=re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[a-zA-Z]{2,}")
URL_RE=re.compile(r'(?:https?://[^\s<>"\'\)]+|www\.[^\s<>"\'\)]+)')
PHONE_RE=re.compile(r"(?:\+\d{1,3}[\s.-]?)?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}(?:[\s.-]?\d{2,4})?")
CARD_RE=re.compile(
  r"\b(?:"

  #Visa
  r"4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}"

  #Mastercard
  r"|5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}"

  #Amex
  r"|3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}"

  #Discover
  r"|6011[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}"

  r")\b"
)

def classify_email(email):
  email= email.lower()
  if email.endswith("@si.alueducation.com"):
    return "ALU SI staff"
  elif email.endswith("@alumni.alueducation.com"):
    return "ALU Alumni"
  elif email.endswith("@alueducation.com"):
    return "ALU Official"
  else:
    return "External"

def is_valid_phone(raw_text):
  digit_count=0
  for character in raw_text:
    if character.isdigit():
      digit_count=digit_count+1
  return 7 <= digit_count<=15

def get_digits_only(text):
  digits=""
  for character in text:
    if character.isdigit():
      digits=digits+character
  return digits

