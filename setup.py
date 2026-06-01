from setuptools import setup, find_packages

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name="zero-day-forge",
    version="1.0.0",
    author="Zero-Day Forge Team",
    description="Advanced Vulnerability Scanner",
    packages=find_packages(),
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'zdf-scan=main:main',
        ],
    },
    python_requires='>=3.8',
)
