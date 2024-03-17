from setuptools import find_packages, setup

setup(
    # Application name:
    name="ankalauncher",
    # Version number (initial):
    version=open("./VERSION").read(),
    # Application author details:
    author="majdoub khalid",
    author_email="majdoub.khalid@gmail.com",
    # Packages
    packages=find_packages(),
    # Include additional files into the package
    include_package_data=True,
    # Details
    url="https://github.com/hadamrd/launcherd2",
    #
    # license="LICENSE.txt",
    description="Launcher reproduction to fetch launcher accounts.",
    long_description=open("README.md").read(),
    # Dependent packages (distributions)
    install_requires=open("./requirements.txt").readlines(),
    classifiers=[
        "Programming Language :: Python :: 3.9",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Windows",
    ],
    python_requires=">=3.9,<3.10",
)
