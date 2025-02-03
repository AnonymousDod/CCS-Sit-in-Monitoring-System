


import cgi
import sqlite3


print("Content-type:text/html\r\n")

form = cgi.FieldStorage()

un= form.getvalue("un")
up = form.getvalue("pwd")

if un=="chandu" and up=="519":
	print("<script>window.location.href='http://localhost:8000/test.html';</script>")
else:
	#if un=="chandu":
	#	print("WRONG PASSWORD")
	#else:
	print("WRONG USERNAME")


cur.close()
con.close()


