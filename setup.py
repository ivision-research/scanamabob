import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

with open("requirements.txt") as fp:
    requirements = fp.readlines()

setuptools.setup(
    name="scanamabob",
    version="0.0.2",
    author="Carve Systems, LLC.",
    author_email="kenneth.wilke@carvesystems.com",
    description="A security toolkit for AWS based environments",
    long_description='# Scanamabob!',
    long_description_content_type="text/markdown",
    url="https://github.com/CarveSystems/scanamabob",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Development Status :: 2 - Pre-Alpha",
        "Operating System :: OS Independent",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Topic :: Security",
        "Topic :: Utilities"
    ],
    scripts=['scripts/scanamabob'],
    install_requires=requirements,
    python_requires='>=3.6',
)

