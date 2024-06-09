from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def generate_and_save_keys():
    """Генерирует пару ключей RSA и сохраняет их в файлы."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Сохранение приватного ключа
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Сохранение публичного ключа
    public_key = private_key.public_key()
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_keys():
    """Загружает пару ключей RSA из файлов."""
    try:
        # Загрузка ключей из файлов
        with open("private_key.pem", "rb") as f:
            private_key_data = f.read()
            private_key = serialization.load_pem_private_key(private_key_data, password=None, backend=default_backend())

        with open("public_key.pem", "rb") as f:
            public_key_data = f.read()
            public_key = serialization.load_pem_public_key(public_key_data, backend=default_backend())

        return public_key, private_key
    except Exception as e:
        print(f"Ошибка при загрузке ключей: {e}")
        return None, None

def serialize_public_key(public_key):
    """Сериализует публичный ключ в формат PEM."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(public_key_bytes):
    """Десериализует публичный ключ из формата PEM."""
    try:
        public_key = serialization.load_pem_public_key(
            public_key_bytes,
            backend=default_backend()
        )
        return public_key
    except Exception as e:
        print(f"Ошибка при загрузке ключа: {e}")
        return None

def rsa_encrypt(message, public_key):
    """Шифрует сообщение с помощью публичного ключа."""
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def rsa_decrypt(encrypted_message, private_key):
    """Расшифровывает сообщение с помощью приватного ключа."""
    decrypted = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()
