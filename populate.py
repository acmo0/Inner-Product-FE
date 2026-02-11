import sqlite3
import os

DB_NAME = "test_db.db"
POPULATION_SIZE = 10_000

if os.path.exists(DB_NAME):
	os.remove(DB_NAME)

con = sqlite3.connect(DB_NAME)
cur = con.cursor()
cur.execute("CREATE TABLE fuzzy_hashes(fh BLOB PRIMARY KEY, type TEXT)")

data = [(os.urandom(32), "nilsimsa") for _ in range(POPULATION_SIZE)]

cur.executemany("INSERT INTO fuzzy_hashes VALUES (?, ?)", data)
con.commit()