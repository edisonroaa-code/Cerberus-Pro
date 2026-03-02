import asyncio
import logging
from aiohttp import web

async def handle_get(request):
    """Simulate extremely delicate SQL endpoint via GET"""
    payload = request.query.get('id', '')
    if "'" in payload:
        # Simulate PostgreSQL Error Traceback
        trace = """
org.postgresql.util.PSQLException: ERROR: syntax error at or near "UNION"
  Position: 42
	at org.postgresql.core.v3.QueryExecutorImpl.receiveErrorResponse(QueryExecutorImpl.java:2553)
	at org.postgresql.core.v3.QueryExecutorImpl.processResults(QueryExecutorImpl.java:2285)
	at org.postgresql.core.v3.QueryExecutorImpl.execute(QueryExecutorImpl.java:323)
	at org.postgresql.jdbc.PgStatement.executeInternal(PgStatement.java:481)
	at org.postgresql.jdbc.PgStatement.execute(PgStatement.java:401)
	at org.postgresql.jdbc.PgStatement.executeWithFlags(PgStatement.java:322)
	at org.postgresql.jdbc.PgStatement.executeCachedSql(PgStatement.java:308)
	at org.postgresql.jdbc.PgStatement.executeWithFlags(PgStatement.java:284)
	at org.postgresql.jdbc.PgStatement.executeQuery(PgStatement.java:236)
	at com.zaxxer.hikari.pool.ProxyStatement.executeQuery(ProxyStatement.java:111)
        """
        return web.Response(text=trace, status=500)
    
    return web.json_response({"status": "ok", "user": {"id": payload, "name": "Fake User"}})

async def handle_post(request):
    """Simulate POST endpoint reading structured JSON for Semantic Evasion testing"""
    try:
        body = await request.json()
        body_text = str(body)
        if "'" in body_text:
            return web.Response(text="org.postgresql.util.PSQLException: ERROR: syntax error at or near ''' \n  Position: 69\n\tat org.postgresql.core.v3.QueryExecutorImpl.execute", status=500)
        return web.json_response({"status": "updated", "data": body})
    except Exception:
        return web.Response(text="Bad Request", status=400)

app = web.Application()
app.router.add_get('/api/user', handle_get)
app.router.add_post('/api/user', handle_post)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    web.run_app(app, host='127.0.0.1', port=8081)
