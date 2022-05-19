#https://rfc5424-logging-handler.readthedocs.io/en/latest/basics.html
from scapy.all import sniff
import logging
from rfc5424logging import Rfc5424SysLogHandler,Rfc5424SysLogAdapter
import rfc5424logging
from random import seed
from random import randint
from datetime import datetime
import binascii

seed(int(datetime.timestamp(datetime.now())))

logger=None

def init_logger(name_logger,syslog_server_ip="127.0.0.1", syslog_server_port="5000",hostname="",appname="",procid=None):
	logger = logging.getLogger(name_logger)
	logger.setLevel(logging.INFO)

	e_id=randint(0, 10000000)

	sh = Rfc5424SysLogHandler(
	    facility=rfc5424logging.LOG_CRON,
	    address=(syslog_server_ip, syslog_server_port),
	    hostname=hostname,
	    appname=appname,
	    procid=procid,
	    enterprise_id=e_id
	)
	logger.addHandler(sh)
	adapter = Rfc5424SysLogAdapter(logger,enable_extra_levels=True)
	
	return adapter


def send_syslog_packet(packet):

	global logger
		
	ip_src=""
	ip_dst=""
	sport=""
	dport=""
	t_proto=""
	app_payload=""
	
	if "IP" in packet:
		ip_src=packet.getlayer("IP").src
		ip_dst=packet.getlayer("IP").dst
		

	if "TCP" in packet:
		t_proto="TCP"
		sport=packet.getlayer("TCP").sport
		dport=packet.getlayer("TCP").dport
		app_payload=binascii.hexlify(bytes(packet.getlayer("TCP").payload)).decode("utf-8")
	
	if "UDP" in packet:
		t_proto="UDP"
		sport=packet.getlayer("UDP").sport
		dport=packet.getlayer("UDP").dport	
		app_payload=binascii.hexlify(bytes(packet.getlayer("UDP").payload)).decode("utf-8")
		
	extra = {'structured_data': { "info": {'ip_addr_src': ip_src,'ip_addr_dst': ip_dst, 'transport_proto': t_proto, 'sport': sport, 'dport': dport,'application_payload': app_payload}}}
	msg="{} {} {} {} {} {}".format(ip_src,ip_dst,t_proto,sport,dport,app_payload)
	print(msg)
	logger.emergency(msg, extra=extra)

	
if __name__ == "__main__":

	logger=init_logger(name_logger="test_scapy",syslog_server_ip="127.0.0.1", syslog_server_port="5000",hostname="",appname="",procid=None)
	sniff(prn=send_syslog_packet)


#Per cambiare il valore del livello associato alla "facility" -> Cambiare la proprieta' "facility" durante l'istanza dell'oggetto Rfc5424SysLogHandler in init_logger -> Valori accettati: https://github.com/jobec/rfc5424-logging-handler/blob/master/rfc5424logging/handler.py#L30

#Per cambiare il valore del livello associato alla "severity/priority" -> Cambiare il metodo invocato per inviare il syslog message tramite l'oggetto "logger" in send_syslog_packet (es. logger.emergency(msg, extra=extra)) -> Per ogni metodo corrisponde ad un livello di severity -> https://github.com/jobec/rfc5424-logging-handler/blob/master/rfc5424logging/adapter.py#L93 -> Per far funzionare il tutto, quando si istanza l'oggetto "adapter" (in init_logger), ricordarsi di settare la proprieta' "enable_extra_levels=True"



