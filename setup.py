from distutils.core import setup
import py2exe

setup(
    console=[{
        'script': 'decryptor.py',
        'uac_info': 'requireAdministrator'
    }],
    options = {'py2exe': {'bundle_files': 1, 'compressed': True}},
    zipfile=None,
)
