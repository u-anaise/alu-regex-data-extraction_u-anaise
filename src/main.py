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

def luhn_check(digits):
  reversed_digits=digits[::-1]
  total=0
  position=0
  for character in reversed_digits:
    digit=int(character)
    if position%2==1
      digit=digit*2
      if digit>9:
        digit=digit-9
    total=total+digit
    position=position+1
  return total%10==0

THREAT_PATTERNS=[
  (re.compile(r"<\s*script.*?>", re.IGNORECASE), "possible script tag (XSS)"),
  (re.compile(r"(--|;)\s*DROP\s+TABLE", re.IGNORECASE), "possible SQL command injection"),
  (re.compile(r"['\"]\s*;\s*--"), "possible SQL comment-out attempt"),
  (re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]"), "contains control characters"),
]

def find_threats(line):
  reasons=[]
  for pattern, reason in THREAT_PATTERNS:
    if pattern.search(line):
      reasons.append(reason)
    return reasons

def mask_email(email):
  parts=email.split("@")
  username=parts[0]
  domain=parts[1]

  if len(username)>2:
    visible_part=username[0:2]
  else:
    visible_part=username[0]
  hidden_part="*" * (len(username)-len(visible_part))
  return visible_part+hidden_part+"@"+domain

def mask_card(card_text):
  digits=get_digits_only(card_text)
  if len(digits)<4:
    return "****"
  last_four=digits[-4:]
  return "**** **** **** "+ last_four

def main():
  found_emails=[]
  found_urls=[]
  found_phones=[]
  found_cards=[]
  flagged_lines=[]

  input_file=open("input/raw_text.txt", "r", encoding="utf-8")
  all_lines=input_file.readlines()
  input_file.close()

  line_number=0
  for line in all_lines:
    line_number=line_number+1
    threats=find_threats(line)
    line_is_flagged=len(threats)>0
    if line_is_flagged:
      flagged_lines.append({
        "line":line_number,
        "reasons": threats,
        "text_preview": line.strip()[:80]
      })

      email_matches=EMAIL_RE.findall(line)
      for email in email_matches:
        found_emails.append({
          "value": email,
          "masked":mask_email(email),
          "category": classify_email(email),
          "line":line_number,
          "flagged":line_is_flagged
        })

      url_matches=URL_RE.findall(line)
      for url in url_matches:
        found_urls.append({
          "value":url,
          "line":line_number,
          "flagged":line_is_flagged
        })

      line_without_cards=line
      card_matches=CARD_RE.findall(line)
      for card in card_matches:
        digits=get_digits_only(card)
        if luhn_check(digits):
          found_cards.append({
            "value":card,
            "masked":mask_card(card),
            "line":line_number,
            "flagged":line_is_flagged
          })
          line_without_cards=line_without_cards.replace(card, " "* len(card))


      phone_matches= PHONE_RE.findall(line_without_cards)
      for phone in phone_matches:
        if is_valid_phone(phone):
          found_phones.append({
            "value": phone.strip(),
            "line": line_number,
            "flagged":line_is_flagged
          })

    print("EXTRACTION SUMMARY")
    print("\nEmails found: ", len(found_emails))
    for item in found_emails:
      flag_note=" [These is the flagged category]" if item["flagged"] else ""
      print(" ", item["masked"], "-", item["category"], flag_note)

    print("\nURLs found:", len(found_urls))
    for item in found_urls:
      print(" ", item["value"])

    print("\nPhone numbers found:", len(found_phones))
    for item in found_phones:
      print(" ", item["value"])

    print("\nCredit cards found (Luhn_checking-valid):", len(found_cards))
    for item in found_cards:
      print(" ", item["masked"])

    print("\nSuspicious lines flagged:", len(flagged_lines))
    for item in flagged_lines:
      print(" Line", item["line"], "-", item["reasons"])

    #Saving full details of the data (unmasked) to the json output file
    results={
      "summary": {
        "emails_found": len(found_emails),
        "urls_found": len(found_urls),
        "phones_found": len(found_phones),
        "cards_found":len(found_cards),
        "flagged_lines":len(flagged_lines)
      },
      "emails": found_emails,
      "urls": found_urls,
      "phone": found_phones,
      "cards": found_cards,
      "threats": flagged_lines
    }

    output_file= open("output/sample-output.json", "w", encoding="utf-8")
    json.dump(results, output_file, indent=2)
    output_file.close()

if __name__=="__main__":
  main()