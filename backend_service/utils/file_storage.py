import os
from utils.storage_interface import Storage

class FileStorage(Storage):
    """
    This class is used to store files.
    """
    def __init__(self, storage_directory='/app/object_storage'):
        self.storage_directory = os.path.abspath(storage_directory)
        if not os.path.exists(self.storage_directory):
            os.makedirs(self.storage_directory, exist_ok=True)
    
    def store(self, filename, contents):
        safe_path = self._get_safe_path(filename)
        if safe_path:
            with open(safe_path, 'wb') as fp:
                fp.write(contents)
        else:
            raise ValueError("Invalid file path")

    def get(self, filename):
        safe_path = self._get_safe_path(filename)
        if safe_path:
            with open(safe_path, 'rb') as fp:
                contents = fp.read()
            return contents
        else:
            raise FileNotFoundError("File not found")

    def delete(self, filename):
        safe_path = self._get_safe_path(filename)
        if safe_path:
            os.remove(safe_path)
        else:
            raise FileNotFoundError("File not found")

    def _get_safe_path(self, filename):
        # Construct the absolute path and normalize it to remove any '..' components
        intended_path = os.path.abspath(os.path.join(self.storage_directory, filename))
        
        # Ensure the final path is still within the storage_directory
        if intended_path.startswith(self.storage_directory):
            return intended_path
        else:
            return None
