# นำเข้า PasswordHasher สำหรับสร้างและตรวจสอบ Password Hash
from argon2 import PasswordHasher

# นำเข้า Type สำหรับระบุให้ใช้อัลกอริทึม Argon2id โดยตรง
from argon2.low_level import Type

# นำเข้า VerifyMismatchError สำหรับจัดการกรณี Password ที่ตรวจสอบไม่ตรงกับ Hash
from argon2.exceptions import VerifyMismatchError


# ---------------------------------------------------------
# Configure Argon2id Password Hasher
# ---------------------------------------------------------
# กำหนดค่าพารามิเตอร์สำหรับอัลกอริทึม Argon2id
# ซึ่งใช้สำหรับสร้าง Password Hash อย่างปลอดภัย
_hasher = PasswordHasher(
    time_cost=3,             # จำนวนรอบการประมวลผล (Iterations / Passes)
    memory_cost=64 * 1024,   # หน่วยความจำที่ใช้ 64 MiB หรือ 65,536 KiB
    parallelism=4,           # จำนวนการประมวลผลแบบขนาน (Parallel Lanes)
    hash_len=32,             # ขนาดของ Hash 32 Bytes หรือ 256 Bits
    salt_len=16,             # ขนาดของ Salt 16 Bytes หรือ 128 Bits
    type=Type.ID             # ระบุให้ใช้อัลกอริทึม Argon2id
)


# ---------------------------------------------------------
# Password Hashing Function
# ---------------------------------------------------------
# ฟังก์ชันรับ Password ในรูปแบบ String
# และสร้าง Argon2id Password Hash
#
# Argon2id จะสร้าง Salt แบบสุ่มให้โดยอัตโนมัติ
# และรวม Algorithm, Parameters, Salt และ Hash
# ไว้ใน Encoded Password Hash ที่คืนกลับมา
def hash_password(password: str) -> str:
    return _hasher.hash(password)


# ---------------------------------------------------------
# Password Verification Function
# ---------------------------------------------------------
# ฟังก์ชันใช้ตรวจสอบ Password ที่ผู้ใช้กรอก
# กับ Argon2id Password Hash ที่จัดเก็บไว้
#
# คืนค่า:
# True  = Password ถูกต้อง
# False = Password ไม่ถูกต้อง
def verify_password(password: str, hashed_password: str) -> bool:
    try:
        return _hasher.verify(hashed_password, password)
    except VerifyMismatchError:
        return False
