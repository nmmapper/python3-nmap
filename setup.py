import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="python3-nmap", # Replace with your own username
    version="0.1.1",
    author="Wangolo Joel",
    author_email="info@nmmapper.com",
    description="Python3-nmap converts Nmap commands into python3 methods",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/wangoloj/python3-nmap",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    setup_requires=['wheel'],
    install_requires=["requests", "sphinx", 'sphinx_rtd_theme'],
)
