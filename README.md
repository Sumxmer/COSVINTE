ให้ รัน ไฟล์ cosvinte.py  จะไปเรียกไฟล์ช่องโหว่ต่างๆ

โปรเจคนี้เป็น script ตรวจสอบ cve ของ linux  โดยเปรียบเทียบเวอร์ชั่น และมีการให้คะแนนCVSS และสร้าง Report เป็นไฟล์ PDF


## Installation
```
python3 -m pip install venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Run
```
python3 cosvinte.py
```
