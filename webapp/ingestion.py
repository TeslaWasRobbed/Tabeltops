"""Kusto table initialization and idempotent timed batch ingestion."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
from pathlib import Path, PurePosixPath
from urllib.request import Request, urlopen

KUSTO_ENDPOINT=os.getenv("KUSTO_ENDPOINT","http://127.0.0.1:8080").rstrip("/")
KUSTO_DATABASE=os.getenv("KUSTO_DATABASE","TabletopSIEM")


def management(csl,database=None):
    payload=json.dumps({"db":database or KUSTO_DATABASE,"csl":csl}).encode()
    request=Request(f"{KUSTO_ENDPOINT}/v1/rest/mgmt",data=payload,headers={"Content-Type":"application/json"},method="POST")
    with urlopen(request,timeout=30) as response:
        return json.loads(response.read().decode())


def ensure_ledger(db):
    db.execute("CREATE TABLE IF NOT EXISTS ingestion_ledger (batch_id TEXT PRIMARY KEY, table_name TEXT NOT NULL, offset_seconds INTEGER NOT NULL, row_count INTEGER NOT NULL, ingested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)")


def load_manifest(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def table_command(table,columns):
    definition=", ".join(f"{column['name']}:{column['type']}" for column in columns)
    return f".create-merge table {table} ({definition})"


def container_path(batch_path,container_root):
    return str(PurePosixPath(container_root)/PurePosixPath(batch_path))


def ingest_batch(batch,container_root):
    path=container_path(batch["path"],container_root).replace('"','\\"')
    management(f'.ingest into table {batch["table"]} (@"{path}") with (format="csv")')


def initialize(manifest_path,state_db,container_root):
    manifest=load_manifest(manifest_path)
    for table,columns in manifest["schemas"].items(): management(table_command(table,columns))
    db=sqlite3.connect(state_db)
    try:
        ensure_ledger(db)
        known={row[0] for row in db.execute("SELECT batch_id FROM ingestion_ledger")}
        for batch in manifest["batches"]:
            if batch["offset_seconds"]>=0 or batch["id"] in known: continue
            ingest_batch(batch,container_root)
            db.execute("INSERT INTO ingestion_ledger(batch_id,table_name,offset_seconds,row_count) VALUES(?,?,?,?)",(batch["id"],batch["table"],batch["offset_seconds"],batch["rows"])); db.commit()
    finally: db.close()


def sync_due(db,elapsed_seconds,manifest_path,container_root):
    """Ingest due scheduled batches; ledger makes polling and restarts safe."""
    manifest=load_manifest(manifest_path); ensure_ledger(db)
    known={row[0] for row in db.execute("SELECT batch_id FROM ingestion_ledger")}
    ingested=0
    for batch in manifest["batches"]:
        if batch["offset_seconds"]<0 or batch["offset_seconds"]>elapsed_seconds or batch["id"] in known: continue
        ingest_batch(batch,container_root)
        db.execute("INSERT INTO ingestion_ledger(batch_id,table_name,offset_seconds,row_count) VALUES(?,?,?,?)",(batch["id"],batch["table"],batch["offset_seconds"],batch["rows"])); db.commit(); known.add(batch["id"]); ingested+=batch["rows"]
    return ingested


def reset_dataset(db, manifest_path, container_root):
    """Clear exercise tables, restore history, and reset the ingestion ledger."""
    manifest=load_manifest(manifest_path); ensure_ledger(db)
    for table in manifest["schemas"]:
        management(f".clear table {table} data")
    db.execute("DELETE FROM ingestion_ledger"); db.commit()
    for batch in manifest["batches"]:
        if batch["offset_seconds"]>=0: continue
        ingest_batch(batch,container_root)
        db.execute("INSERT INTO ingestion_ledger(batch_id,table_name,offset_seconds,row_count) VALUES(?,?,?,?)",(batch["id"],batch["table"],batch["offset_seconds"],batch["rows"])); db.commit()


if __name__=="__main__":
    parser=argparse.ArgumentParser(); parser.add_argument("command",choices=["initialize"]); parser.add_argument("--manifest",required=True); parser.add_argument("--state-db",default=str(Path(__file__).parent/"data"/"tabletop.db")); parser.add_argument("--container-root",default="/kustodata/tabletop"); args=parser.parse_args()
    if args.command=="initialize": initialize(args.manifest,args.state_db,args.container_root); print("Kusto tables and historical batches are ready.")
