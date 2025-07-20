# Windows Installation Guide

This guide helps you install the NIDS system on Windows, particularly addressing the scikit-learn compilation issue.

## Prerequisites

### Option 1: Install Microsoft Visual C++ Build Tools (Recommended)

1. Download Microsoft Visual C++ Build Tools from:
   https://visualstudio.microsoft.com/visual-cpp-build-tools/

2. Run the installer and select:
   - **Workloads** → **C++ build tools**
   - **Individual components** → **MSVC v143 - VS 2022 C++ x64/x86 build tools**

3. Install and restart your computer

### Option 2: Use Pre-compiled Wheels (Alternative)

If you don't want to install the build tools, you can use pre-compiled wheels:

```bash
# Activate your virtual environment
venv\Scripts\activate

# Install using pre-compiled wheels
pip install --only-binary=all scikit-learn numpy pandas scipy
```

## Installation Steps

### 1. Automated Setup (Recommended)

```bash
# Run the setup script
python setup.py
```

The setup script will automatically detect Windows and use the appropriate installation method.

### 2. Manual Installation

If the automated setup fails, try manual installation:

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
venv\Scripts\activate

# Upgrade pip
python -m pip install --upgrade pip

# Install core scientific libraries first
pip install numpy pandas scipy

# Install scikit-learn
pip install scikit-learn

# Install remaining requirements
pip install -r requirements-windows.txt
```

### 3. Alternative: Use Conda (If Available)

If you have Anaconda or Miniconda installed:

```bash
# Create conda environment
conda create -n nids python=3.9

# Activate environment
conda activate nids

# Install scientific packages via conda
conda install scikit-learn numpy pandas scipy

# Install remaining packages via pip
pip install -r requirements.txt
```

## Troubleshooting

### Issue: "Microsoft Visual C++ 14.0 or greater is required"

**Solution 1:** Install Microsoft Visual C++ Build Tools (see Prerequisites above)

**Solution 2:** Use pre-compiled wheels:
```bash
pip install --only-binary=all scikit-learn
```

**Solution 3:** Use conda instead of pip:
```bash
conda install scikit-learn
```

### Issue: "Failed to install scikit-learn"

**Solution:** Try installing in this order:
```bash
pip install numpy
pip install scipy
pip install scikit-learn
```

### Issue: Network interface not found

**Solution:** Update the `.env` file with a valid network interface:
```env
# Common Windows interfaces
INTERFACE=Ethernet    # For wired connection
INTERFACE=Wi-Fi       # For wireless connection
INTERFACE=lo          # For loopback testing
```

To find available interfaces, run:
```bash
python -c "import psutil; print(list(psutil.net_if_addrs().keys()))"
```

## Running the System

After successful installation:

```bash
# Activate virtual environment
venv\Scripts\activate

# Start the NIDS system
python run.py

# Or use the batch file
start_nids.bat
```

## Verification

1. **Check API Documentation**: http://localhost:8000/docs
2. **Run Health Check**: http://localhost:8000/api/v1/health
3. **Run Demo**: `python demo.py`

## Support

If you continue to have issues:

1. Check that you're using Python 3.8 or higher
2. Ensure your virtual environment is activated
3. Try using conda instead of pip
4. Install Microsoft Visual C++ Build Tools
5. Check the logs in the `logs/` directory

For additional help, check the main README.md file or create an issue in the repository. 