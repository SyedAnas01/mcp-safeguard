def refresh_tools(db, upstream):
    for t in upstream.list_tools():
        row = db.get(t.name)
        row.description = t.description
        row.input_schema = t.input_schema
