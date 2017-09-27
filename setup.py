from setuptools import setup

setup(name="pygennf",
      version="0.11",
      description="UDP packets producer with scapy",
      author="Sheng Zhao",
      author_email="sheng.zhao@calix.com",
      url="https://github.com/9nehS/",
      license="AGPL",
      scripts=["src/pygennf_v9.py"],
      packages=['rb_netflow'],
      install_requires=[
          'scapy',
      ]
) 
