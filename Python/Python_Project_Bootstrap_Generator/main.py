import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

TEMPLATE = {
    "src": [],
    "tests": [],
    ".github": ["workflows"],
}

FILES = {
    "README.md": "# Project Title\n\nGenerated automatically.",
    "requirements.txt": "",
    ".gitignore": "venv/\n__pycache__/",
    "LICENSE": f"Copyright {datetime.now().year}",
}

def validate_path_length(project_path):
    if os.name == 'nt':
        max_limit = 260
        safe_limit = 200
    else:
        max_limit = 4096
        safe_limit = 1000

    path_length = len(str(project_path))

    print(f"\nProject path length: {path_length}")

    if path_length > max_limit:
        raise Exception(f"Path too long! Max allowed is {max_limit} characters.")

    elif path_length > safe_limit:
        print("Warning: Path is long and may cause issues on some tools.")

    else:
        print("Path length is safe.")

def get_user_dependencies():
    deps = input("Enter required Third Party Python modules (comma-separated, e.g. streamlit,pandas,msal):\n> ")
    
    # # Clean and split input
    # dependencies = [d.strip() for d in deps.split(",") if d.strip()]

    dependencies = []

    for d in deps.split(","):
        cleaned = d.strip()
        
        if cleaned:
            dependencies.append(cleaned)
    
    return dependencies

def get_pip_path(project_name):
    if os.name == 'nt':  # Windows
        return os.path.join(project_name, "venv", "Scripts", "pip.exe")
    else:  # Linux/macOS
        return os.path.join(project_name, "venv", "bin", "pip")

def create_project(project_name):
    # project_path = os.path.abspath(project_name)
    root = Path(project_name).resolve()
    validate_path_length(root)
    # os.makedirs(project_path, exist_ok=True)
    # os.chdir(project_path)
    root.mkdir(parents=True, exist_ok=True)

    print(f"Creating structure in: {root}")

    # Create folder structure
    for folder, subfolders in TEMPLATE.items():
        # os.makedirs(folder, exist_ok=True)
        f_path = root / folder
        f_path.mkdir(exist_ok=True)
        for sf in subfolders:
            # os.makedirs(os.path.join(folder, sf), exist_ok=True)
            (f_path / sf).mkdir(exist_ok=True)

    # Get dependencies from user
    dependencies = get_user_dependencies()

    # Create base files
    for filename, content in FILES.items():
        file_path = root / filename
        with open(file_path, "w") as f:
            if filename == "requirements.txt":
                f.write("\n".join(dependencies))
            else:
                f.write(content)

     # Initialize Git
    # subprocess.run(["git", "init", project_path], check=True)
    subprocess.run(["git", "init", str(root)], check=True)

    # Create virtual environment
    # subprocess.run([sys.executable, "-m", "venv", os.path.join(project_path, "venv")], check=True)
    subprocess.run([sys.executable, "-m", "venv", str(root / "venv")], check=True)

    # Install dependencies using venv pip
    pip_path = get_pip_path(root)

    # Upgrade pip INSIDE venv
    subprocess.run([pip_path, "install", "--upgrade", "pip"], check=True)

    if dependencies:
        print("\n Installing dependencies...")
        subprocess.run([pip_path, "install"] + dependencies, check=True)

        # Freeze exact versions back to requirements.txt
        # with open("requirements.txt", "w") as f:
        #     subprocess.run([pip_path, "freeze"], stdout=f)

        freeze = input("Freeze versions? (y/n): ").lower()

        if freeze == "y":
            with open(root / "requirements.txt", "w") as f:
                subprocess.run([pip_path, "freeze"], stdout=f)

    print(f"\n Project '{root}' created successfully with dependencies!")

# Run
if __name__ == "__main__":
    enter_project_name = input("Please enter you desired Python project name(Ex: Automation_For_MS_Entra_ID_Devices):\n> ")
    create_project(enter_project_name)