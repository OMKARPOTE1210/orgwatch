import PyInstaller.__main__
import os
import sys

# 1. Setup Absolute Paths
# Get the folder where this script (build_installer.py) lives
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SERVICE_DIR = os.path.join(BASE_DIR, 'service')
OUTPUT_DIR = os.path.join(BASE_DIR, 'resources')
AGENT_SCRIPT = os.path.join(SERVICE_DIR, 'agent.py')
OUTPUT_EXE = os.path.join(OUTPUT_DIR, 'orgwatch_daemon.exe')

# Debugging: Print paths
print(f"DEBUG: Base Directory: {BASE_DIR}")
print(f"DEBUG: Service Directory: {SERVICE_DIR}")
print(f"DEBUG: Looking for Agent at: {AGENT_SCRIPT}")

# 2. Verify Files Exist
if not os.path.exists(AGENT_SCRIPT):
    print(f"❌ ERROR: agent.py NOT found at {AGENT_SCRIPT}")
    print("Please verify the file exists in the 'service' folder.")
    sys.exit(1)

required_assets = [
    'rules.yar', 
    'malware_model.pkl', 
    'phishing_model.pkl', 
    'behavior_model.pkl', 
    'nids_model.pkl'
]

print("🔍 Checking for required assets...")
missing = []
for asset in required_assets:
    path = os.path.join(SERVICE_DIR, asset)
    if not os.path.exists(path):
        missing.append(asset)

if missing:
    print(f"❌ ERROR: Missing files in 'service' folder: {', '.join(missing)}")
    print("👉 Run 'python train_ai.py' first to generate models.")
    print("👉 Ensure 'rules.yar' is created in the service folder.")
    sys.exit(1)

# 3. Clean Previous Build
if os.path.exists(OUTPUT_EXE):
    try:
        os.remove(OUTPUT_EXE)
        print("🧹 Cleaned previous build.")
    except Exception as e:
        print(f"⚠️ Warning: Could not remove old EXE: {e}")

# 4. Compile with PyInstaller
print("🚀 Compiling OrgWatch Agent...")

PyInstaller.__main__.run([
    AGENT_SCRIPT,
    '--onefile',
    '--name=orgwatch_daemon',
    '--noconsole',  # Hide console window (Lowers heuristic score)
    '--uac-admin',  # Request Admin privileges (Legitimizes system access)
    f'--distpath={OUTPUT_DIR}',
    f'--workpath={os.path.join(BASE_DIR, "build", "py_temp")}',
    f'--specpath={os.path.join(BASE_DIR, "build", "py_spec")}',
    '--clean',
    
    # Asset Bundling (Source;Dest) - Windows uses ; separator
    f'--add-data={os.path.join(SERVICE_DIR, "rules.yar")};.',
    f'--add-data={os.path.join(SERVICE_DIR, "malware_model.pkl")};.',
    f'--add-data={os.path.join(SERVICE_DIR, "phishing_model.pkl")};.',
    f'--add-data={os.path.join(SERVICE_DIR, "behavior_model.pkl")};.',
    f'--add-data={os.path.join(SERVICE_DIR, "nids_model.pkl")};.',

    # Hidden Imports (Critical for AI/System libs)
    '--hidden-import=yara',
    '--hidden-import=wmi',
    '--hidden-import=win10toast',
    '--hidden-import=pystray',
    '--hidden-import=PIL',
    # '--hidden-import=uiautomation', # REMOVED: Often flagged by AV as spyware/screen reader
    '--hidden-import=sklearn.ensemble',
    '--hidden-import=sklearn.tree',
    '--hidden-import=sklearn.neighbors',
    '--hidden-import=sklearn.utils._cython_blas',
    '--hidden-import=sklearn.utils._typedefs',
    '--hidden-import=scipy.special.cython_special',
    '--hidden-import=joblib',
    '--hidden-import=pefile',
    '--hidden-import=watchdog.observers.read_directory_changes',
    '--hidden-import=win32timezone',
    '--hidden-import=pythoncom',
    '--hidden-import=pywintypes',
])

print(f"\n✅ Build Complete! Executable located at: {OUTPUT_EXE}")