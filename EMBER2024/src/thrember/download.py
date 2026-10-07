import os
import zipfile
import argparse
from huggingface_hub import hf_hub_download, list_repo_files
VALID_SPLITS = ["all", "train", "test", "challenge"]
VALID_FILES = ["all", "PE", "Win32", "Win64", "Dot_Net", "APK", "ELF", "PDF"]
def is_dir(file_path):
    if not os.path.isdir(file_path):
        raise ValueError("Invalid directory: {}".format(file_path))
    return file_path
def download_dataset(download_dir, split="all", file_type="all"):
    if not is_dir(download_dir):
        raise ValueError("Not a directory: {}".format(download_dir))
    if split not in VALID_SPLITS:
        raise ValueError("split must be in {}".format(", ".join(VALID_SPLITS)))
    if file_type not in VALID_FILES:
        raise ValueError("file_type must be in {}".format(", ".join(VALID_FILES)))
    os.chdir(download_dir)
    splits = VALID_SPLITS[1:]
    if split != "all":
        splits = [split]
    file_types = VALID_FILES[2:]
    if file_type == "PE":
        file_types = ["Win32", "Win64", "Dot_Net"]
    elif file_type != "all":
        file_types = [file_type]
    for split in splits:
        if split == "challenge":
            continue
        for file_type in file_types:
            file_name = "{}_{}.zip".format(file_type, split)
            zip_path = hf_hub_download(repo_id="joyce8/EMBER2024", filename=file_name, repo_type="dataset")
            print("Unzipping...")
            with zipfile.ZipFile(zip_path, "r") as f:
                f.extractall(".")
            os.remove(zip_path)
    if "challenge" in splits:
        zip_path = hf_hub_download(repo_id="joyce8/EMBER2024", filename="challenge.zip", repo_type="dataset")
        with zipfile.ZipFile(zip_path, "r") as f:
            f.extractall(".")
        os.remove(zip_path)
    return
def download_models(download_dir):
    if not is_dir(download_dir):
        raise ValueError("Not a directory: {}".format(download_dir))
    os.chdir(download_dir)
    repo_id = "joyce8/EMBER2024-benchmark-models"
    model_files = [file_name for file_name in list_repo_files(repo_id) if file_name.endswith(".model")]
    for file_name in model_files:
        hf_hub_download(repo_id=repo_id, filename=file_name, local_dir=download_dir)
    return
