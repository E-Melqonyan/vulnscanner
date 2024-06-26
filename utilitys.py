import time
# import debugpy
import functools

# def attach_debugger():
#     debugpy.listen(5678)
#     debugpy.wait_for_client()

def time_it(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        elapsed_time = end_time - start_time
        print(f'{func.__name__} took {elapsed_time:.2f} seconds')
        return result
    return wrapper