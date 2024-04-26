# test_redebug.py

import os
import tempfile
import shutil
from subprocess import run

def create_temp_dir_with_files(files):
    temp_dir = tempfile.mkdtemp()
    for filename, content in files.items():
        filepath = os.path.join(temp_dir, filename)
        with open(filepath, 'w') as file:
            file.write(content)
    return temp_dir

def run_redebug(patch_content, source_content, command_args=[]):
    with tempfile.TemporaryDirectory() as temp_dir:
        patch_path = os.path.join(temp_dir, 'test_patch.diff')
        source_path = os.path.join(temp_dir, 'test_source.txt')

        with open(patch_path, 'w') as patch_file:
            patch_file.write(patch_content)

        with open(source_path, 'w') as source_file:
            source_file.write(source_content)

        command = ['python', 'redebug.py', patch_path, source_path] + command_args
        result = run(command, capture_output=True, text=True)

        return result

# Test Case 1: Basic test with minimal input
patch_content = """--- a/test_file.txt
+++ b/test_file.txt
@@ -1,3 +1,3 @@
-line 1
-line 2
-line 3
+modified line 1
+modified line 2
+modified line 3
"""
source_content = """modified line 1
modified line 2
modified line 3
"""

result = run_redebug(patch_content, source_content)
print(result.stdout)

# Test Case 2: Test with verbose mode
result_verbose = run_redebug(patch_content, source_content, ['-v'])
print(result_verbose.stdout)

