# PYrus
Python script to upload files to Virus Total and then display results in therminal

Usage:pyrus.py <filename>

Important notes: You need your own API key from virus total. Unfortunately they only support 4 queries per minute, so if pyrus locks up, just force quit and wait a minute. By default, pyrus will wait 20 seconds between each query to prevent locking up. So the only time that should happen is if you call the script too many times in a minute.
