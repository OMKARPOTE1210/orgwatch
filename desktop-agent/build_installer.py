import PyInstaller.__main__
import os

# 1. Compile Python Service into a standalone EXE
print("Compiling Python Agent...")
PyInstaller.__main__.run([
    'service/agent.py',
    '--onefile',
    '--name=orgwatch_daemon',
    '--distpath=resources', # Output to resources folder
    '--clean',
    '--hidden-import=sklearn.ensemble',
    '--hidden-import=sklearn.tree',
    '--hidden-import=sklearn.utils._cython_blas',
    '--hidden-import=sklearn.neighbors.typedefs',
    '--hidden-import=sklearn.neighbors.quad_tree',
    '--hidden-import=sklearn.tree._utils',
])
print("Python Compilation Complete. Created resources/orgwatch_daemon.exe")