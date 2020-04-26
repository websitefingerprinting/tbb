import multiprocessing as mp 
import logging
import os
from os import makedirs
from os.path import join, abspath, dirname, pardir
import numpy as np
import subprocess
import argparse
from scapy.all import *
import glob

src1 = '10.0.0.4'
src2 = '10.0.0.5'
src3 = '10.0.0.6'
src4 = '10.0.0.7'
src5 = '10.0.1.4'
src6 = '10.0.1.5'
src7 = '10.0.1.6'
src8 = '10.0.1.8'

CELL_SIZE = 512
#CELL+ TLS HEADER + MY HEADER
MY_CELL_SIZE = CELL_SIZE + 31 + 3
isDummy = 888
isReal = 1

captured_file_name = 'capture.pcap.filtered'
ParsedDir = join(abspath(join(dirname(__file__), pardir)) , "parsed")

def init_directories(path):
    # Create a results dir if it doesn't exist yet
    if not os.path.exists(path):
        makedirs(path)


def getTimestamp(pkt, t0):
    return float(pkt.time - t0)


def getDirection(pkt):
    if (pkt.payload.src == src1) or (pkt.payload.src == src2) or (pkt.payload.src == src3) or (pkt.payload.src == src4)\
    or (pkt.payload.src == src5) or (pkt.payload.src == src6) or (pkt.payload.src == src7) or (pkt.payload.src == src8):
        return 1
    else:
        return -1 

def parse_arguments():

    parser = argparse.ArgumentParser(description='Parse captured traffic.')

    parser.add_argument('dir',
                        type=str,
                        metavar='<dataset path>',
                        help='Path of dataset.')
    parser.add_argument('-mode',
                        type=str,
                        metavar='<parse mode>',
                        help='The type of dataset: clean, burst?.')
    parser.add_argument('-m',
                        action='store_true', 
                        default=False,
                        help='The type of dataset: is mon or unmon?.')
    parser.add_argument('-suffix',
                        type=str,
                        metavar='<parsed file suffix>',
                        default='.cell',
                        help='to save file as xx.suffix')

    # Parse arguments
    args = parser.parse_args()
    return args

def findall(p, s):
    '''Yields all the positions of
    the pattern p in the string s.'''
    i = s.find(p)
    while i != -1:
        yield i
        i = s.find(p, i+1)

def get_cells(tls_str,cum_times,cum_bytes, dire):

    cells = []

    assert cum_bytes[-1] == len(tls_str)
    cum_bytes = np.array(cum_bytes)
    cum_times = np.array(cum_times)
    for k,ind in enumerate(findall(b'\x17\x03\x03', tls_str)):
        start_byte_ind = ind+5 - CELL_SIZE
        tls_len = int.from_bytes(tls_str[ind+3:ind+5], 'big')
        num_cell = int(np.round(tls_len/CELL_SIZE))
#         print("start ind:{}, num cell:{}".format(ind+5, num_cell))
        for i in range(num_cell):
            start_byte_ind += CELL_SIZE
            tmp = cum_times[cum_bytes >= start_byte_ind]
            if len(tmp) > 0:
                pkt_t = tmp[0]
            else:
                pkt_t = cum_times[-1]
                # print("END")
#             print("#{}, abs byte {}, rela byte {}, t:{}".format(k, start_byte_ind, start_byte_ind-ind, pkt_t))
            cells.append([pkt_t, dire])
    return cells   

# def clean_parse(fdir):
#     global savedir, suffix, ismon
#     batch,site,inst = fdir.split("/")[-2].split("_")
#     if ismon:
#         savefiledir = join(savedir, site+"-"+inst+suffix) 
#     else:
#         savefiledir = join(savedir, site+suffix)
#     packets = rdpcap(fdir)

#     try:
#         t0 = packets[0].time
#         in_pkts = []
#         out_pkts = []
#         out_tls_str = b""
#         in_tls_str = b""
#         out_cum_bytes = [0]
#         in_cum_bytes = [0]
#         out_cum_times = [0]
#         in_cum_times = [0]

#         for i,pkt in enumerate(packets):
#             payload = pkt.load
#             dire = getDirection(pkt)
#             t = getTimestamp(pkt, t0)
#             if dire == 1:
#                 out_tls_str += payload
#                 out_cum_bytes.append(len(out_tls_str))
#                 out_cum_times.append(t)
#             else:
#                 in_tls_str += payload
#                 in_cum_bytes.append(len(in_tls_str))
#                 in_cum_times.append(t)
#         out_pkts = get_cells(out_tls_str,out_cum_times,out_cum_bytes,1)
#         in_pkts = get_cells(in_tls_str,in_cum_times,in_cum_bytes,-1)
#         #sort packets
#         total_pkts_unsorted = np.array(in_pkts + out_pkts)
#         total_pkts0 = total_pkts_unsorted[total_pkts_unsorted[:,0].argsort(kind = "mergesort")]
#         with open(savefiledir, 'w') as f:
#             for pkt in total_pkts0:
#                 f.write("{:.6f}\t{:.0f}\n".format(pkt[0],pkt[1])) 
#     except Exception as e: 
#       print("Error in {}: {}".format(fdir.split('/')[-1], e))

def clean_parse(fdir):
    global savedir, suffix, ismon
    batch,site,inst = fdir.split("/")[-2].split("_")
    if ismon:
        savefiledir = join(savedir, site+"-"+inst+suffix) 
    else:
        savefiledir = join(savedir, site+suffix)
    packets = rdpcap(fdir)

    try:
        with open(savefiledir, 'w') as f:
            start = 0
            t0 = packets[0].time
            # for i, pkt in enumerate(packets):
            #     #skip the first few noise packets
            #     if getDirection(pkt)>0 :
            #         start = i
            #         t0 = pkt.time
            #         print("Start from pkt no. {}".format(start))
            #         break

            for i, pkt in enumerate(packets[start:]):
                b = raw(pkt.payload.payload.payload)
                byte_ind = b.find(b'\x17\x03\x03')
                while byte_ind != -1 and byte_ind < len(b):
                    if b[byte_ind:byte_ind + 3] == b'\x17\x03\x03':
                        TLS_LEN = int.from_bytes(b[byte_ind+3:byte_ind+5], 'big')
                        cur_time = getTimestamp(pkt,t0)
                        cur_dir = getDirection(pkt)
                        #complete TLS record
                        cell_num = TLS_LEN /CELL_SIZE
                        cell_num = int(np.round(cell_num))
                     
                        for i in range(cell_num):
                            f.write("{:.6f}\t{:d}\n".format(cur_time, cur_dir))
                        byte_ind += TLS_LEN + 5
                    else:
                        #What happened here?
                        break
    except Exception as e:
        print("Error in {}, {} ".format(fdir.split('/')[-1], e))


def burst_parse(fdir):
    global savedir, suffix, ismon
    batch,site,inst = fdir.split("/")[-2].split("_")
    if ismon:
        savefiledir = join(savedir, site+"-"+inst+suffix) 
    else:
        savefiledir = join(savedir, site+suffix)

    packets = rdpcap(fdir)
    try:
        t0 = packets[0].time

        in_pkts_raw = []
        in_pkts = []
        out_pkts = []
        out_pkts_raw = []
        for i,pkt in enumerate(packets):
            payload = pkt.load
            dire = getDirection(pkt)
            t = getTimestamp(pkt, t0)
            if dire == 1:
                out_pkts_raw.append([t,payload])
            else:
                #incoming ones are more complicated, first collect raw packets
                in_pkts_raw.append([t, payload])

        #process outgoing ones      
        ind = 0
        while ind < len(out_pkts_raw):
            if len(out_pkts_raw[ind][1]) % MY_CELL_SIZE == 0:
                break   
            #skip fragments in the head
            print("Skip outgoing pkt #{}".format(ind))
            ind += 1 
        while ind < len(out_pkts_raw):
            base_pkt = out_pkts_raw[ind]
            cum_payload = base_pkt[1]
            cum_bytes = [len(cum_payload)]
            cum_times = [base_pkt[0]]
            while ind < len(out_pkts_raw)-1 and len(cum_payload) % MY_CELL_SIZE != 0:
                #fragment
                ind += 1
                tmp_pkt = out_pkts_raw[ind]
                cum_payload += tmp_pkt[1]
                cum_bytes.append(len(cum_payload))
                cum_times.append(tmp_pkt[0])
            # print("cum_bytes:{}\ncum_times:{}".format(cum_bytes,cum_times))
            for b in range(0, len(cum_payload), MY_CELL_SIZE):
                pkttype = isDummy if cum_payload[b]>0 else isReal
                # print(b,np.where(np.array(cum_bytes)>=b))
                pkttime = cum_times[np.where(np.array(cum_bytes)>=b)[0][0]]
                out_pkts.append([pkttime, pkttype])         
            ind += 1

        #process incoming ones 
        ind = 0
        while ind < len(in_pkts_raw):
            if len(out_pkts_raw[ind][1]) % MY_CELL_SIZE == 0:
                break
            #skip fragments in the head
            # print("Skip incoming pkt #{}".format(ind))
            ind += 1 
        while ind < len(in_pkts_raw):
            base_pkt = in_pkts_raw[ind]
            cum_payload = base_pkt[1]
            cum_bytes = [len(cum_payload)]
            cum_times = [base_pkt[0]]
            while ind < len(in_pkts_raw)-1 and len(cum_payload) % MY_CELL_SIZE != 0:
                #fragment
                ind += 1
                tmp_pkt = in_pkts_raw[ind]
                cum_payload += tmp_pkt[1]
                cum_bytes.append(len(cum_payload))
                cum_times.append(tmp_pkt[0])
            for b in range(0, len(cum_payload), MY_CELL_SIZE):
                pkttype = isDummy if cum_payload[b]>0 else isReal
                pkttime = cum_times[np.where(np.array(cum_bytes)>=b)[0][0]]
                in_pkts.append([pkttime, pkttype * (-1)])           
            ind += 1

        #sort packets
        total_pkts_unsorted = np.array(in_pkts + out_pkts)
        total_pkts0 = total_pkts_unsorted[total_pkts_unsorted[:,0].argsort(kind = "mergesort")]
        with open(savefiledir, 'w') as f:
            for pkt in total_pkts0:
                f.write("{:.6f}\t{:.0f}\n".format(pkt[0],pkt[1])) 
    except Exception as e: 
        print("Error in {}: {}".format(fdir.split('/')[-1], e))

if __name__ == "__main__":
    global savedir, suffix, ismon
    args = parse_arguments()
    suffix = args.suffix
    ismon = args.m
    # filelist = glob.glob(join(args.dir,'*_*_*' ,'capture.pcap.filtered'))
    filelist_ = glob.glob(join(args.dir,'*_*_*' ,'screenshot_0.png'))
    filelist = []
    #Sanity check
    for f in filelist_:
        pcapfile = join(f.split("screenshot_0.png")[0], captured_file_name)
        if os.path.exists(pcapfile):
            filelist.append(pcapfile)

    filename = args.dir.rstrip("/").split("/")[-1]
    savedir = join(ParsedDir, filename)
    init_directories(savedir)
    print("Parsed file in {}".format(savedir))
    # for f in filelist:
    #   parse(f)
    print("Totol:{}".format(len(filelist)))

    pool = mp.Pool(processes=15)
    if args.mode == 'clean':
        # pool.map(clean_parse, filelist)
        pool.map(clean_parse, filelist)
    elif args.mode == 'burst':
        pool.map(burst_parse, filelist)
    else:
        raise Error('Wrong mode:{}'.format(args.mode))

    zipcmd = "zip -rq " + savedir.rstrip("/") + ".zip" + " " + savedir
    print(zipcmd)
    subprocess.call(zipcmd, shell=True)

