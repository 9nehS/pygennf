from setuptools import setup

setup(name="pygennf",
      version="0.11",
      description="Netflow packets generator with scapy",
      author="Sheng Zhao",
      author_email="sheng.zhao@calix.com",
      url="https://github.com/9nehS/",
      license="AGPL",
      scripts=["src/pygennf_v9.py", "src/pygennf_v9_multi_threads.py"],
      packages=['rb_netflow', 'web_api', 'src'],
      # packages=find_packages(),
      install_requires=[
          'scapy',
          'flask'
      ]
      )
