from pathlib import Path
import os
import re
import subprocess

infra_file = Path("brownrook-infra/kubernetes/platform/idc/20-deployment.yaml")
text = infra_file.read_text()

infra_commit = subprocess.check_output(
    ["git", "-C", "brownrook-infra", "rev-parse", "HEAD"],
    text=True,
).strip()

version = Path("VERSION").read_text().strip()
git_commit = os.environ["GITHUB_SHA"]
build_number = os.environ["GITHUB_RUN_NUMBER"]
image_ref = f"ghcr.io/larocquemb/brownrook-idc:{git_commit}"

def replace(pattern: str, replacement: str, content: str) -> str:
    new_content, count = re.subn(pattern, replacement, content, flags=re.MULTILINE)
    if count == 0:
        raise RuntimeError(f"Pattern not found: {pattern}")
    return new_content

# update container image
text = replace(
    r'(^\s*image:\s*)ghcr\.io/larocquemb/brownrook-idc[:@][^\s"]+',
    rf'\1{image_ref}',
    text,
)

# update APP_VERSION
text = replace(
    r'(^\s*- name:\s*APP_VERSION\s*\n\s*value:\s*)(.*)',
    rf'\1"{version}"',
    text,
)

# update GIT_COMMIT
text = replace(
    r'(^\s*- name:\s*GIT_COMMIT\s*\n\s*value:\s*)(.*)',
    rf'\1"{git_commit}"',
    text,
)

# update INFRA_COMMIT
text = replace(
    r'(^\s*- name:\s*INFRA_COMMIT\s*\n\s*value:\s*)(.*)',
    rf'\1"{infra_commit}"',
    text,
)

# update BUILD_NUMBER
text = replace(
    r'(^\s*- name:\s*BUILD_NUMBER\s*\n\s*value:\s*)(.*)',
    rf'\1"{build_number}"',
    text,
)

# update IMAGE_REF
text = replace(
    r'(^\s*- name:\s*IMAGE_REF\s*\n\s*value:\s*)(.*)',
    rf'\1"{image_ref}"',
    text,
)

# optional cleanup: remove IMAGE_COMMIT if it still exists
text = re.sub(
    r'^\s*- name:\s*IMAGE_COMMIT\s*\n\s*value:\s*.*\n',
    '',
    text,
    flags=re.MULTILINE,
)

infra_file.write_text(text)

print("Updated deployment metadata:")
print(f"  APP_VERSION  = {version}")
print(f"  GIT_COMMIT   = {git_commit}")
print(f"  INFRA_COMMIT = {infra_commit}")
print(f"  BUILD_NUMBER = {build_number}")
print(f"  IMAGE_REF    = {image_ref}")
