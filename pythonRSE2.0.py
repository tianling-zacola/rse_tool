import secrets
import hashlib
import os

def hashgen(string):
    # 将字符串编码为字节
    byte_string = string.encode('utf-8')
    # 创建哈希对象
    hash_object = hashlib.sha256()
    # 更新哈希对象
    hash_object.update(byte_string)
    # 获取十六进制格式的哈希值
    hex_dig = hash_object.hexdigest()
    return hex_dig

def keygen(key,length):#密钥派生函数
    key=hashgen(str(key))
    seed=hashgen(str(length))
    length=length * 2
    result=''
    cnt=0
    for __count in range(int(((length - length % 64) / 64))):
        seed = hashgen(key + seed)
        result += seed
    if length % 64 != 0:
        seed = hashgen(key + seed)
        result += seed[0:(length % 64)]
    return bytes.fromhex(result)
    
def filesz(file_path):
    # 检查文件是否存在
    if not os.path.exists(file_path):
        return None  # 或者抛出异常，根据你的需求决定
    # 获取文件大小
    file_size = os.path.getsize(file_path)
    return file_size

def xor(file_data, key_data):
    # 确保两个输入都是字节序列
    if not isinstance(file_data, bytes) or not isinstance(key_data, bytes):
        raise ValueError("Both inputs must be of type 'bytes'.")
    # 确保两个序列长度相同
    min_length = min(len(file_data), len(key_data))
    file_data = file_data[:min_length]
    key_data = key_data[:min_length]

    # 执行按位异或操作
    xor_result = bytearray()
    for byte, key_byte in zip(file_data, key_data):
        xor_result.append(byte ^ key_byte)

    return xor_result

def encrypt_file(file_path, key):#加密主函数
    file_size = filesz(file_path)
    with open(file_path, 'rb') as f:
        with open(file_path + '.rse2', 'wb') as out_file:
            while True:
                file_data = f.read(1024 * 1024)  # 每次读取1MB
                if not file_data:
                    break
                key_data = key[:len(file_data)]  # 获取等长的密钥数据
                output = xor(file_data, key_data)  # 创建加密序列
                output = bytes(output[::-1])  # 将结果倒转为 bytes 类型
                key_data = key[len(file_data):]  # 获取后半段密钥数据
                output = xor(output, key_data)  # 再次XOR操作
                out_file.write(output)  # 写入加密后的数据

def decrypt_file(file_path, key):#解密主函数
    file_size = filesz(file_path)
    #file_path = file_path[:-5]
    with open(file_path, 'rb') as f:
        with open(file_path[:-5], 'wb') as out_file:
            while True:
                file_data = f.read(1024 * 1024)  # 每次读取1MB
                if not file_data:
                    break
                key_data = key[len(file_data):]  # 获取后半段密钥数据
                output = xor(file_data, key_data)  # 创建加密序列
                output = bytes(output[::-1])  # 将结果倒转为 bytes 类型
                key_data = key[:len(file_data)]  # 获取前半段密钥数据
                output = xor(output, key_data)  # 再次XOR操作
                out_file.write(output)  # 写入加密后的数据


def main():
    # 示例使用
    fpath = input('请输入文件路径：')
    fsz = filesz(fpath) * 2
    print(fsz)  # 文件长度
    pwd = input('请输入密钥：')
    print('生成密钥中，请稍等.....')
    key = keygen(pwd, fsz)  # 生成密钥
    print('生成密钥完毕')
    if not fpath.endswith('.rse2'):
        print('加密中')
        encrypt_file(fpath, key)  # 加密文件
        print('完成')
    else:
        print('解密中')
        decrypt_file(fpath, key)
        print('完成')
    
main()
