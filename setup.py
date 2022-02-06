from setuptools import setup


setup(
    name='nucypher_async',
    version='1.0',
    description='Async testing',
    packages=['nucypher_async'],
    install_requires=[
        'trio',
        'hypercorn[trio]',
        'Quart',
        'quart-trio',
        'httpx',
        'cryptography',
        'nucypher-core',
        'maya',
        ],
    extras_requires={
        'dev': [
            'pytest',
            'pytest-trio',
        ]
    },
    entry_points={'console_scripts': [
        'nucypher_async = nucypher_async.cli:main',
        ]},
    )
