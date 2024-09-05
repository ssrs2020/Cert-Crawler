import socket
import ssl


def get_domain_cert(domain):
    """
    obtain certificate info
    :param domain: str
    :return: dict
    """
    socket.setdefaulttimeout(5)

    cxt = ssl.create_default_context()
    skt = cxt.wrap_socket(socket.socket(), server_hostname=domain)

    skt.connect((domain, 443))
    cert = skt.getpeercert()

    skt.close()

    return cert


if __name__ == "__main__":
    print(get_domain_cert("www.baidu.com"))