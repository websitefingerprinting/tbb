import subprocess
import os
from os import makedirs
from os.path import join, abspath, dirname, pardir
import glob
import re
import argparse
import time
import numpy as np
Pardir = abspath(join(dirname(__file__), pardir))
DumpDir = join( Pardir , "dataset")

MON_SITE_NUM = 100

def parse_arguments():

	parser = argparse.ArgumentParser(description='Combine parsed datasets')

	parser.add_argument('-dir',
						nargs='+',
						type=str,
						metavar='<batch dir>',
						dest = 'dirlist',
						default = [],
						help='bacth folders')
	parser.add_argument('-m',
						action='store_true', 
						default=False,
						help='The type of dataset: is mon or unmon?.')
	parser.add_argument('-mode',
						type=str,
						metavar='<dataset type>',
						choices=['clean', 'dp', 'tamaraw','wt'],
						help='clean or defended?:clean, dp, tamaraw, walkie talkie')	
	parser.add_argument('-t',
						type=str,
						metavar='<T>',
						default='20',
						help='param T')	
	parser.add_argument('-e',
						type=str,
						metavar='<epsilon>',
						default='05',
						help='param epsilon')	
	parser.add_argument('-l',
						type=str,
						metavar='<L>',
						default='100',
						help='param L')	
	parser.add_argument('-w',
						type=str,
						metavar='<W>',
						default='6',
						help='param W')	

	parser.add_argument('-suffix',
						type=str,
						metavar='<suffix>',
						default='.cell',
						help='suffix of the file')

	# Parse arguments
	args = parser.parse_args()
	return args

def init_directories(ismon, t, l, e, w):
	# Create a results dir if it doesn't exist yet
	if not os.path.exists(DumpDir):
		makedirs(DumpDir)

	if ismon:
		world = 'mon'
	else:
		world = 'unmon'

	# Define output directory
	# timestamp = time.strftime('%m%d_%H%M')
	if args.mode == 'clean':
		output_dir = join(DumpDir, world+"_clean")
	elif args.mode == 'tamaraw':
		output_dir = join(DumpDir, world+"_tamaraw")
	elif args.mode == 'wt':
		output_dir = join(DumpDir, world+"_wt")
	elif args.mode == 'dp':
		output_dir = join(DumpDir, world+"_T"+t+"_L"+l+"_E"+e+"_W"+w)
	else:
		raise ValueError("Wrong dataset type!")
	makedirs(output_dir)

	return output_dir

if __name__ == '__main__':
	args = parse_arguments()
	folders = args.dirlist
	output_dir = init_directories(args.m, args.t, args.l, args.e, args.w)
	print("Mode:{}, Create fold {}".format(args.mode,output_dir))


	cnt = [0]*MON_SITE_NUM
	for folder in folders:
		files = glob.glob(join(folder, "*"+args.suffix))
		for file in files:
			if args.m:

				tmp = file.split("/")[-1].split(args.suffix)[0]
				label = int(tmp.split("-")[0])
				# inst  = int(tmp.split("-")[1])
				newinst = cnt[label]
				cnt[label] += 1
				# if label in cnt.keys():
				# 	newinst = cnt[label]
				# 	cnt[label] += 1
				# else:
				# 	newinst = 0
				# 	cnt[label] = 1

				newfiledir = join( output_dir, str(label) + '-' + str(newinst) +args.suffix)
				cmd = "cp " + file + " " + newfiledir
				subprocess.call(cmd, shell = True) 
			else:
				#unmon to do
				pass 
				# oldlabel = int(file.split("/")[-1].split(args.suffix)[0])
				# if oldlabel in selected_list:
				# 	newlabel = np.where(selected_list==oldlabel)[0][0]
				# 	newfiledir = join( output_dir, str(newlabel) +args.suffix)
				# 	cmd = "cp " + file + " " + newfiledir
				# 	# print(cmd)
				# 	subprocess.call(cmd, shell = True) 
	
	if args.m:
		#to do
		pass
		# tmp = output_dir.rstrip("/").split("/")[-1]
		# mon_dir = join(targetdir, "mon_" + tmp.split("unmon_")[-1])
		# cmd = "mv " + join(output_dir, "*") +  " " + mon_dir
		# # print(cmd)
		
		# subprocess.call(cmd,shell=True)

	for i in range(MON_SITE_NUM):
		print("#{}:{}".format(i, cnt[i]))

