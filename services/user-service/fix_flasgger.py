import os
import sys

def fix_flasgger():
    try:
        from markupsafe import Markup
    except ImportError:
        print("markupsafe is not installed.")
        sys.exit(1)

    flasgger_base_path = os.path.join(sys.prefix, 'Lib', 'site-packages', 'flasgger', 'base.py')
    flasgger_utils_path = os.path.join(sys.prefix, 'Lib', 'site-packages', 'flasgger', 'utils.py')
    
    if not os.path.isfile(flasgger_base_path):
        print(f"flasgger base.py file not found at {flasgger_base_path}.")
        sys.exit(1)

    if not os.path.isfile(flasgger_utils_path):
        print(f"flasgger utils.py file not found at {flasgger_utils_path}.")
        sys.exit(1)

    # Fix base.py
    with open(flasgger_base_path, 'r') as file:
        base_content = file.read()

    base_content = base_content.replace("from flask.json import JSONEncoder", "from flask.json.provider import DefaultJSONProvider as JSONEncoder")
    base_content = base_content.replace("from flask import Markup", "from markupsafe import Markup")

    with open(flasgger_base_path, 'w') as file:
        file.write(base_content)

    # Fix utils.py
    with open(flasgger_utils_path, 'r') as file:
        utils_content = file.read()

    utils_content = utils_content.replace("import imp", "import importlib.util")

    # Replace imp.load_source
    utils_content = utils_content.replace("imp.load_source", "importlib.util.module_from_spec")

    # Add spec and exec_module for module loading
    if "exec_module" not in utils_content:
        utils_content = utils_content.replace(
            "importlib.util.module_from_spec", 
            "from importlib.util import spec_from_file_location, module_from_spec\n"
        )
        utils_content = utils_content.replace(
            "module_from_spec('module.name', '/path/to/file.py')",
            "spec = spec_from_file_location('module.name', '/path/to/file.py')\n" + \
            "foo = module_from_spec(spec)\n" + \
            "spec.loader.exec_module(foo)"
        )

    with open(flasgger_utils_path, 'w') as file:
        file.write(utils_content)

    print("flasgger files updated successfully.")

if __name__ == "__main__":
    fix_flasgger()
