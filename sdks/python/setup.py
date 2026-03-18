from setuptools import setup, find_packages

setup(
    name="swiftauth-sdk",
    version="1.0.0",
    description="Official SwiftAuth SDK for Python",
    author="SwiftAuth",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "requests>=2.28.0",
        "websocket-client>=1.6.0",
    ],
)
