
import hashlib
import os
from Crypto.Cipher import AES
import time
from Crypto.Util.Padding import pad, unpad
import random
import shutil
from pathlib import Path

import hmac
dencrypt_folder="/host/picde"  
def update_aes_key(prev_hash, aes_key):
    hmac_sha256 = hmac.new(prev_hash, aes_key, hashlib.sha256)
    new_key = hmac_sha256.digest()[:32]
    return new_key


def encrypt_status(status, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_status = cipher.encrypt(pad(status.encode('utf-8'), AES.block_size))
    return encrypted_status


def decrypt_status(encrypted_status, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_status = unpad(cipher.decrypt(encrypted_status), AES.block_size)
    return decrypted_status.decode('utf-8')

def get_image_hash(file_path):
    try:
        with open(file_path, 'rb') as f:
            img_data = f.read()
        hash_object = hashlib.sha256(img_data)
        return hash_object.hexdigest()
    except FileNotFoundError:
        print(f"文件 {file_path} 未找到。")
        return None
    except Exception as e:
        print(f"发生错误: {e}")
        return None

def decrypt_image(file_path, key):
    with open(file_path, 'rb') as f:
        iv = f.read(16) 
        encrypted_data = f.read()
    cipher = AES.new(key[:16], AES.MODE_CBC, iv) 
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    output_path = os.path.join(dencrypt_folder, os.path.basename(file_path).replace('.encrypted', ''))
    with open(output_path, 'wb') as f:
        f.write(decrypted_data)


matrix = []
already_read = []
def DORAM(total_files, max_index, i):
    global matrix 
    if i == 0:
        all_numbers = list(range(total_files))
        random.shuffle(all_numbers) 
        matrix = [all_numbers[j * max_index:(j + 1) * max_index] for j in range((total_files + max_index - 1) // max_index)]
        if len(matrix[-1]) < max_index:
            remaining_numbers = list(set(range(total_files)) - set(all_numbers))
            while len(matrix[-1]) < max_index:
                matrix[-1].append(remaining_numbers.pop() if remaining_numbers else random.randint(0, total_files - 1))
    if not matrix:
        print("所有行数据均已被读取！")
        return None

    readrow = random.randrange(len(matrix))  
    row_data = matrix.pop(readrow) 

    random.shuffle(matrix) 
    return sorted(row_data)

def process_decrypt_images_in_folder(folder_path, total_files, max_index):
    if not os.path.exists(dencrypt_folder):
        os.makedirs(dencrypt_folder)
    aes_key = b'v \xf35$\x90{\xbd-\xa2v\xc3\xbf\xb0\xf3\xa3'
    iv = b'initialvector123'  
    prev_hash = ''
    count=0
    while True:
        ORAMbuf = DORAM(total_files, max_index, count)
        count+=1
        print(f"生成的 ORAMbuf 数组: {ORAMbuf}")
        if ORAMbuf is None:
            break

        random_file_index = random.choice(ORAMbuf)  
        random_file_index_position = ORAMbuf.index(random_file_index)  
        print(f"随机选取的文件编号: {random_file_index}")

        prev_hash_str = prev_hash.hex() if prev_hash else ''  

        status_SGX = f"selected_file={random_file_index}|status=1|ORAMbuf={ORAMbuf}|{prev_hash_str}"
 
        print("status_SGX=", status_SGX)
        statusfile='/host/status_SGX.txt'
        status_encrypted = encrypt_status(status_SGX, aes_key[:16], iv)
        with open(statusfile, 'wb') as status_file:
            status_file.write(status_encrypted)
        statusfile_clients='/host/status_client.txt'
        #-------------------------------------------------------
        while True:
            if os.path.exists(statusfile_clients):
                time.sleep(0.1)
                with open(statusfile_clients, 'rb') as status_clients:
                    encrypted_status = status_clients.read()
                try:
                    status = decrypt_status(encrypted_status, aes_key[:16], iv)
                    print("解密信号status==",status)
                except Exception as e:
                    print(f"解密 status_client.txt 时出错: {e}")
                    status = None
                if status == '1': 
                    print("加密程序已处理完成，继续解密。")
                    os.remove(statusfile_clients)  
                    break
                elif status == 'end':
                    print("接收到结束信号，解密程序结束。")
                    os.remove(statusfile_clients)  
                    return
                else:
                    time.sleep(0.1)
            else:
                time.sleep(0.1)  
        encrypted_files = []
        print("os.path.isdir(folder_path)=",os.path.isdir(folder_path))
        with os.scandir(folder_path) as it:
            for entry in it:
                if entry.is_file() and entry.name.lower().endswith('.encrypted'):
                    encrypted_files.append(entry.name)
        encrypted_files = sorted(encrypted_files, key=lambda x: Path(x).stem)
        if not encrypted_files:
            print("没有加密文件，等待加密程序发信号。")
            time.sleep(1)
            continue
        
        start_timekey = time.time()
        if not prev_hash:
            decrypt_key = aes_key
        else:
            decrypt_key = update_aes_key(prev_hash,aes_key)
        endtimekey = time.time()
        timegen = endtimekey - start_timekey
        print(f"密钥生成完成，运行时间是: {timegen} 秒")

        for index, file in enumerate(encrypted_files):  
       
            file_path = os.path.join(folder_path, file)
      
            decrypt_image(file_path, decrypt_key)
         
            os.remove(file_path)

            prev_image_path = os.path.join(dencrypt_folder, os.path.basename(file).replace('.encrypted', ''))
            if index==random_file_index_position:
                hash_dir=prev_image_path       
        prev_hash = get_image_hash(hash_dir).encode('utf-8')

if __name__ == "__main__":
    import csv
    total_files_list = [512,1024, 2048, 4096,8192]  
    max_index_list = [64]   

    csv_file_path = "/host/COCO_entimes.csv"

    with open(csv_file_path, mode='w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)

        csv_writer.writerow(["Total Files", "Max Index", "Decryption Time (s)"])

        for total_files in total_files_list:
            for max_index in max_index_list:
                print(f"正在测试：Total Files = {total_files}, Max Index = {max_index}")

                encrypted_folder = "/host/picen"

                start_time = time.time()
                process_decrypt_images_in_folder(encrypted_folder, total_files, max_index)
                end_time = time.time()
                decryption_time = end_time - start_time
                print(f"解密完成，运行时间是: {decryption_time} 秒")

                csv_writer.writerow([total_files, max_index, decryption_time])

    print(f"测试完成，结果已保存到 CSV 文件：{csv_file_path}")
