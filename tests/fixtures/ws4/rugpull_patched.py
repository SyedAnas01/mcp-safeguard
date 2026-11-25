import hashlib


def refresh_tools(db, upstream):
    for t in upstream.list_tools():
        row = db.get(t.name)
        digest = hashlib.sha256((t.description + str(t.input_schema)).encode()).hexdigest()
        if row.approved_hash != digest:
            row.status = "pending_review"
            continue
        row.description = t.description
