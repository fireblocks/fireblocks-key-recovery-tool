class RecoveryError(Exception):
    pass


class RecoveryErrorMetadataNotFound(RecoveryError):
    def __init__(self, zip_file_path: str):
        super().__init__(f"Backup zip {zip_file_path} doesn't contain metadata.json")


class RecoveryErrorUnknownChainCode(RecoveryError):
    def __init__(self):
        super().__init__("chain code in metadata.json is missing or invalid")


class RecoveryErrorRSAKeyImport(RecoveryError):
    pass


class RecoveryErrorIncorrectRSAKey(RecoveryError):
    pass
