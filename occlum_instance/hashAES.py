import hashlib
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import time
import shutil  
import re
import hmac


def update_aes_key(prev_hash, aes_key):

    hmac_sha256 = hmac.new(prev_hash, aes_key, hashlib.sha256)
    new_key = hmac_sha256.digest()[:32] 
    return new_key

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

def encrypt_image(file_path, key, output_folder):
    with open(file_path, 'rb') as f:
        iv = f.read(16) 
        img_data = f.read()
    cipher = AES.new(key[:16], AES.MODE_CBC) 
    padded_data = pad(img_data, AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    iv = cipher.iv 
    file_name = os.path.basename(file_path) + '.encrypted'
    output_path = os.path.join(output_folder, file_name)
    with open(output_path, 'wb') as f:
        f.write(iv + encrypted_data)

def encrypt_status(status, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_status = cipher.encrypt(pad(status.encode('utf-8'), AES.block_size))
    return encrypted_status

def decrypt_status(encrypted_status, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_status = unpad(cipher.decrypt(encrypted_status), AES.block_size)
    return decrypted_status.decode('utf-8')

def process_images_in_folder(folder_path, output_folder, max_images):

    shutil.rmtree(output_folder, ignore_errors=True)
    os.makedirs(output_folder, exist_ok=True)

    aes_key = b'v \xf35$\x90{\xbd-\xa2v\xc3\xbf\xb0\xf3\xa3'
    iv = b'initialvector123' 
    image_count = 0
    prev_hash = ''

    print("当前工作目录:", os.getcwd())
    all_files = []
    if not os.path.exists(folder_path):
        print("文件夹不存在")
        exit()
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.lower().endswith(('.jpg', '.jpeg', '.png', '.bmp')):
                all_files.append(os.path.join(root, file))

    while image_count < max_images:
        while True:
            if os.path.exists('status_SGX.txt'):
                time.sleep(0.1)
                with open('status_SGX.txt', 'rb') as status_file:
                    encrypted_status = status_file.read()
                try:
                    status = decrypt_status(encrypted_status, aes_key[:16], iv)  
                    print("解密SGX状态文件status_message=", status)
                except Exception as e:
                    print(f"解密status_SGX.txt 时出错: {e}")
                    status = None
                if status.startswith("selected_file="):
                    orambuf_match = re.search(r'ORAMbuf=\[(.*?)\]', status)
 
                    if orambuf_match:
                        orambuf_str = orambuf_match.group(1)  
                        ORAMbuf = list(map(int, orambuf_str.split(','))) 
                        print("ORAMbuf==",ORAMbuf)
                    else:
                        print("未能从状态中提取 ORAMbuf 数组") 
                        return None, None

                    prev_hash_match = re.search(r'\|([a-fA-F0-9]+)$', status[14:])
                    if prev_hash_match:
                        prev_hash_hex = prev_hash_match.group(1) 
                        try:
                            prev_hash_bytes = bytes.fromhex(prev_hash_hex)
                        except ValueError as e:
                            print(f"无法转换 prev_hash，错误: {e}")
                            prev_hash_bytes = None
                    else:
                        print("未能从状态中提取 prev_hash")
                        prev_hash_bytes = None
                    os.remove('status_SGX.txt') 
                    break
                elif status == 'end':
                    print("接收到结束信号，程序结束。")
                    return
                else:
                    time.sleep(0.1)
            else:
                time.sleep(0.1)
        prev_hash=prev_hash_bytes 
        if not prev_hash:
                encrypt_key = aes_key
        else:
            encrypt_key = update_aes_key(prev_hash,aes_key)
        print("encrypt_key=",encrypt_key)
        for index in ORAMbuf:
            if image_count >= max_images:
                break
            if index < 0 or index >= len(all_files):
                continue
            file_path = all_files[index]
            encrypt_image(file_path, encrypt_key, output_folder)
            image_count += 1

        status_encrypted = encrypt_status("1", aes_key[:16], iv)
        with open('status_client.txt', 'wb') as status_file:
            status_file.write(status_encrypted)

    encrypted_end_signal = encrypt_status("end", aes_key[:16], iv)
    with open('status_client.txt', 'wb') as status_file:
        status_file.write(encrypted_end_signal)

if __name__ == "__main__":
    import csv
    total_files_list = [512,1024, 2048, 4096,8192]  
    max_index_list = [64]     
    csv_file_path = "COCO_detimes.csv"

    with open(csv_file_path, mode='w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(["Total Files", "Max Index", "encryption Time (s)"])
        for total_files in total_files_list:
            for max_index in max_index_list:
                print(f"正在测试：Total Files = {total_files}, Max Index = {max_index}")
                start_time = time.time()
                data_path = "./data/COCO"
                output_folder = './picen'
                process_images_in_folder(data_path, output_folder, total_files)
                end_time = time.time()
                time_difference = end_time - start_time
                print("运行时间是: ", time_difference)
                csv_writer.writerow([total_files, max_index, time_difference])

    print(f"测试完成，结果已保存到 CSV 文件：{csv_file_path}")