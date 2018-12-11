from pyrad import server, packet, dictionary
from pymongo import MongoClient
import hashlib
import logging
import ipaddress
import yaml
import os
import binascii
import socket

if not os.path.exists(path=os.path.join(os.path.dirname(__file__), "logs")):
    os.mkdir(os.path.join(os.path.dirname(__file__), "logs"))

logging.basicConfig(filename=os.path.join(os.path.dirname(__file__), "logs", "radius_server.log"), level="INFO", format="%(asctime)s [%(levelname)-8s] %(message)s")

def get_clients(srv):
    doc = yaml.load(open(os.path.join(os.path.dirname(__file__), "clients", "address.yml"), 'r').read())
    for entry in doc:
        if doc[entry]['type_net'] == "subnet":
            net = ipaddress.IPv4Network(doc[entry]['IP'])
            numbers = int(str(net[-1]).split(".")[-1]) - int(str(net[0]).split(".")[-1])
            for i in range(0,numbers+1):
                srv.hosts[str(net[i])] = server.RemoteHost(str(net[i]), bytes(doc[entry]['secret'], 'utf-8'), doc[entry]['name'])
        elif doc[entry]['type_net'] == "ip":
            srv.hosts[doc[entry]['IP']] = server.RemoteHost(doc[entry]['IP'], bytes(doc[entry]['secret'], 'utf-8'), doc[entry]['name'])

    hostname = socket.gethostname()
    IPAddr = socket.gethostbyname(hostname)
    srv.BindToAddress(str(IPAddr))

    logging.info("Server listen on IP {}, port 1812".format(str(IPAddr)))

class RADIUSserver(server.Server):

    _collection = None

    def checkAccess(self, user, password):

        if self._collection is None:
            client = MongoClient('mongodb://127.0.0.1:27017/')
            self._collection = client['test']['radiusDB']

        return self._collection.count({'_id': password, 'user': user})

    def _HandleAuthPacket(self, pkt):
        server.Server._HandleAuthPacket(self, pkt)
        logging.info(msg="Received an authentication request from {0}".format(pkt['NAS-IP-Address'][0]))
        '''
        for attr in pkt.keys():
            print("%s: %s" % (attr, pkt[attr]))
        '''
        reply = self.CreateReplyPacket(pkt)

        if len(pkt['User-Name']) > 0:
            try:
                pwd = hashlib.sha256(pkt.PwDecrypt(pkt['User-Password'][0]).encode("utf-8")).hexdigest()
                if self.checkAccess(user=pkt['User-Name'][0], password=pwd) > 0:
                    logging.info(msg="Correct access from {0} with user {1}".format(pkt['NAS-IP-Address'][0], pkt['User-Name'][0]))
                    reply.code = packet.AccessAccept
                else:
                    logging.info(msg="Incorrect user credentials from {0} with user {1}".format(pkt['NAS-IP-Address'][0], pkt['User-Name'][0]))
                    reply.code = packet.AccessReject
            except Exception as error:
                logging.info(msg="Incorrect shared secret in access from {0} with user {1}".format(pkt['NAS-IP-Address'][0], pkt['User-Name'][0]))
                reply.code = packet.AccessReject
            finally:
                self.SendReplyPacket(pkt.fd, reply)

if __name__ == '__main__':

    # create server and read dictionary
    srv = RADIUSserver(dict=dictionary.Dictionary(os.path.join(os.path.dirname(__file__), "dictionary", "dictionary.txt")))
    # add clients (address, secret, name)
    get_clients(srv=srv)
    # start server
    srv.Run()
