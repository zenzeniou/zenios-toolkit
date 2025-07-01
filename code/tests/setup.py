from setuptools import setup,find_packages

setup(
    name='zenios-saca-toolkit-project',
    author='Zenios Zeniou',
    description='A comprehensive security analysis and cryptography toolkit',
    url='https://gitlab.ti.howest.be/ti/2024-2025/s2/scripting-and-code-analysis/projects/zenios-zeniou/zenios-saca-toolkit-project',
    install_requires=[
        'bandit',
        'cryptography',
        'scapy',
        'nmap',
        'selenium',
        'qrcode',
        'requests',
        'bs4',
        # For other dependencies please refer to the requirements.txt
    ]
)
