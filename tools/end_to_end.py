import requests
import time
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {
    'http': 'http://localhost:8080',
    'https': 'https://localhost:8080',
}


def req(f, url, data=None):
    print(url)
    f(url, data=data, proxies=proxies, verify=False)
    input("Press [Enter] to send next request...")


req(requests.post, 'https://www.webscantest.com/datastore/search_by_id.php', data={"id": 1})
req(requests.get, 'https://www.webscantest.com/datastore/getimage_by_id.php?id=1')

req(requests.post, 'https://www.webscantest.com/datastore/search_by_name.php', data={"name": "Rake"})
req(requests.get, 'https://www.webscantest.com/datastore/getimage_by_name.php?name=Rake')

req(requests.get, 'https://www.webscantest.com/datastore/search_get_by_id.php?id=3')
req(requests.get, 'https://www.webscantest.com/datastore/search_get_by_name.php?name=Rake')

req(requests.post, 'https://www.webscantest.com/datastore/search_double_by_name.php', data={"name": "Rake"})
req(requests.post, 'https://www.webscantest.com/datastore/search_single_by_name.php', data={"name": "Rake"})
