#!/usr/bin/python3

import socket
import csv
import argparse

from progress.bar import Bar


parser = argparse.ArgumentParser(description='Exein Training Receiver')
parser.add_argument('-p', '--port', type=int, dest='udp_port', default=8888,
                    help='UDP server port')
parser.add_argument('-t', '--tag', type=int, dest='tag', default=39346,
                    help='Monitor tag')
parser.add_argument('-s', '--dataset-size', type=int, dest='dsize', default=100000,
                    help='Dataset size')

args = parser.parse_args()

UDP_IP = "0.0.0.0"
UDP_PORT = args.udp_port
tag = args.tag
dsize = args.dsize

bar = Bar('Processing', max=dsize)


def chunks(lst, n):
    for i in range(0, len(lst), n):
        yield int.from_bytes(lst[i:i + n], "little")

def connect():
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.bind((UDP_IP, UDP_PORT))
	receive(sock)

def receive(sock):
	try:
		with open(str(tag) + '-hooks.csv', 'w', encoding='iso-8859-1', newline='') as csvfile:
			w = csv.writer(csvfile)
			while True:
				data, addr = sock.recvfrom(1450)

				field_len = 2
				index = list(chunks(data[0:150], field_len))

				data = data[150:]
				for i,d in enumerate(index):
					bar.next()
					if index[i+1] != 0:
						end_p = False
						dd = data[index[i]*2:index[i+1]*2]
					else:
						end_p = True
						dd = data[index[i]*2:]

					lst_b = list(chunks(dd[2:], field_len))
					hookid = lst_b[2]
					pid = lst_b[1]

					start_f = lst_b[3]
					end_f = lst_b[4]
					size_f = lst_b[0]
					n_f = end_f - start_f

					seq_pos = n_f + 5

					seq = lst_b[seq_pos]

					start_list = [0] * (start_f - 3)

					end_list = [0] * (size_f - end_f)

					final_list = [hookid, pid, tag]
					final_list.extend(start_list)
					final_list.extend(lst_b[4:seq_pos])
					final_list.extend(end_list)
					final_list.append(seq)

					w.writerow(final_list)
					if end_p:
						break
	except KeyboardInterrupt:
		bar.finish()


def main():
	connect()

if __name__ == "__main__":
	main()
