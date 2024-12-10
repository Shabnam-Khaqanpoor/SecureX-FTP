import os


def resolve_path(user_directory, path):
    """
    Resolves an absolute path from a given path (relative or absolute).
    """
    if path == '.':
        directory = os.path.dirname(path)
        return user_directory, directory

    # elif os.path.isabs(path):
    #     directory= os.path.dirname(path)
    #     return path,directory

    try:
        if not os.path.isabs(path):
            resolved_path = os.path.join(user_directory, path)

            try:
                directory = os.path.dirname(resolved_path)
            except Exception as e:
                return f"Error occurred while returning dir name: {e}"

            return resolved_path, directory
        elif os.path.isabs(path):
            try:
                directory = os.path.dirname(path)
            except Exception as e:
                return f"Error occurred while returning dir name: {e}"

            return path, directory

    except Exception as e:
        return f"Could not resolve path because {e}"

# -----------------------------------------------------------------------------------------------------------------------
