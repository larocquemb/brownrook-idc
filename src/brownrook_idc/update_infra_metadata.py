from pathlib import Path
import os
import re

p = Path("brownrook-infra/kubernetes/platform/idc/20-deployment.yaml")
text = p.read_text()

version = Path("VERSION").read_text().strip()
git_commit = os.environ["GITHUB_SHA"]
build_number = os.environ["GITHUB_RUN_NUMBER"]
image_ref = f"ghcr.io/larocquemb/brownrook-idc:{git_commit}"

text = re.sub(
    r'image:\s*ghcr\.io/larocquemb/brownrook-idc[:@][^\s"]+',
    f'image: {image_ref}',
    text,
)

text = re.sub(
    r'(- name: APP_VERSION\s+value:\s+)".*"',
    rf'\1"{version}"',
    text,
)

text = re.sub(
    r'(- name: GIT_COMMIT\s+value:\s+)".*"',
    rf'\1"{git_commit}"',
    text,
)

text = re.sub(
    r'(- name: BUILD_NUMBER\s+value:\s+)".*"',
    rf'\1"{build_number}"',
    text,
)

text = re.sub(
    r'(- name: IMAGE_REF\s+value:\s+)".*"',
    rf'\1"{image_ref}"',
    text,
)

p.write_text(text)
print(f"Updated image={image_ref}, version={version}, build={build_number}")
