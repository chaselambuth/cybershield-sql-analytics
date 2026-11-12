"""Loopback-only agent server; deliberately independent of PostgreSQL startup."""
from waitress import serve
from cybershield.web import create_app

if __name__=='__main__':
    print('CyberShield investigation agent: http://127.0.0.1:8766/investigate',flush=True)
    serve(create_app(),host='127.0.0.1',port=8766,threads=4,max_request_body_size=32_000)
