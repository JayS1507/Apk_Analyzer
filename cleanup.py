#!/usr/bin/env python3
import os
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BACKEND = ROOT / 'backend'
FRONTEND = ROOT / 'frontend'

# Directories we can safely purge (regenerated or outputs)
PURGE_DIRS = [
	BACKEND / 'uploads',
	BACKEND / 'output',
	BACKEND / 'reports',
	FRONTEND / 'node_modules',
	FRONTEND / 'build',
]

# Files we can safely remove if present
PURGE_FILES = [
	FRONTEND / 'package-lock.json',
]

# Dot-cache dirs
CACHE_DIRS = [
	ROOT / '.cache',
	ROOT / '.parcel-cache',
	ROOT / '.turbo',
]

def remove_path(p: Path):
	try:
		if p.is_symlink() or p.is_file():
			p.unlink(missing_ok=True)
		elif p.is_dir():
			shutil.rmtree(p, ignore_errors=True)
		print(f"Removed: {p}")
	except Exception as e:
		print(f"Skip {p}: {e}")

if __name__ == '__main__':
	print('Cleaning generated artifacts...')
	for d in PURGE_DIRS + CACHE_DIRS:
		remove_path(d)
	for f in PURGE_FILES:
		remove_path(f)
	# Recreate required backend dirs
	for d in [BACKEND / 'uploads', BACKEND / 'output', BACKEND / 'reports']:
		os.makedirs(d, exist_ok=True)
	print('Done.')
