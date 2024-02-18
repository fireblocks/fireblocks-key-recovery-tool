import difflib
from zipfile import ZipFile

class RecoveryError(Exception):
    pass


def find_closest_match_in_zip(zip_file_path, filename):
    with ZipFile(zip_file_path, 'r') as zipfile:
        file_names = zipfile.namelist()
        candidates = difflib.get_close_matches(filename, file_names, n=1, cutoff=0.3)
        candidate = candidates[0] if candidates else None
        return candidate

class FileNotFoundInZip(RecoveryError):
    @staticmethod
    def format_error(zip_file_path, target):
        closest_match = find_closest_match_in_zip(zip_file_path, target)
        if type(closest_match) is not str:
            return f"Backup zip '{zip_file_path}' doesn't contain '{target}'"
        else:
            return f"Backup zip '{zip_file_path}' doesn't contain '{target}'. Note: the closest match is '{closest_match}'"
    
    def __init__(self, zip_file_path: str, target: str):
        super().__init__(self.format_error(zip_file_path,target))

class RecoveryErrorMetadataNotFound(FileNotFoundInZip):
    def __init__(self, zip_file_path: str):
        super().__init__(zip_file_path,'metadata.json')


class RecoveryErrorUnknownChainCode(RecoveryError):
    def __init__(self):
        super().__init__("chain code in metadata.json is missing or invalid")


class RecoveryErrorRSAKeyImport(RecoveryError):
    pass


class RecoveryErrorIncorrectRSAKey(RecoveryError):
    pass
