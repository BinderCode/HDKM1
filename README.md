

## HDKM

HDKM: A Secure and Efficient Dynamic Key Management Scheme for Edge Computing



## Welcome Cite

Zhao Bai, Yaran Duan, Nianyun Song, et al. HDKM: A dynamic key management scheme based on data for real-time updates[C]. Conference on Information and Knowledge Management. 2025.



## How to Run

This tutorial is written under the assumption that you have Docker installed and use Occlum in a Docker container.

Occlum is compatible with glibc-supported Python, we employ miniconda as python installation tool. You can import PyTorch packages using conda. Here, miniconda is automatically installed by install_python_with_conda.sh script, the required python and PyTorch packages for this project are also loaded by this script. Here, we take occlum/occlum:0.23.0-ubuntu18.04 as example.

Step 1 (on the host): Start an Occlum container
```
docker pull occlum/occlum:0.23.0-ubuntu18.04
docker run -it --name=pythonDemo --device /dev/sgx/enclave occlum/occlum:0.23.0-ubuntu18.04 bash
```

Step 2 (in the Occlum container): Download miniconda and install python to prefix position.
```
cd /root/demos/pytorch
bash ./install_python_with_conda.sh
```

Step 3 Install HDKM package in SGX

```
./python-occlum/bin/pip install python~=3.8.0  cryptography~=44.0.2 numpy~=1.21.5 scipy~=1.7.0 Pillow~=9.4.0 tqdm~=4.61.1 scikit-learn~=0.24.2 colorama~=0.4.4 pykeops~=2.1 pyyaml~=6.0 pycryptodome
```



Step 4 (in the Occlum container): Run the server code on Occlum

```
cd /root/demos/pytorch
bash ./run_pytorch_on_occlum.sh
```



Step 5 Install Anaconda in your docker

Refer to [Anaconda | The Operating System for AI](https://www.anaconda.com/)



Step 6 Install HDKM environments in anaconda3

```
conda create -n your-conda-name
source activate your-conda-name
conda install python~=3.8.0 cryptography~=44.0.2 numpy~=1.21.5 scipy~=1.7.0 Pillow~=9.4.0 tqdm~=4.61.1 opencv-python~=4.5.3.56 scikit-learn~=0.24.2 colorama~=0.4.4 pykeops~=2.1 pyyaml~=6.0
```



Step 7  Open a new window and Run clients code 

```
docker exec -it yourdocker /bin/bash
conda activate yourcondaname
cd /root/demos/pytorch/occlum_instance
python hashAES.py
```



