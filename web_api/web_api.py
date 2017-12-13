from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/')
def help():
    return jsonify(
        # 'API (application/json)': 'PATH, notes ?org-id=<orgId> currently required',
        {'Cache clean': '/marketing/cache/clean?org-ids=<org-ids>',
         'Cache clean and rebuild': '/marketing/cache/clean-rebuild?org-ids=<org-ids>&rebuild-table=true',
         'Cache status': '/marketing/cache/status',
         'On board': '/marketing/onboard?org-ids=<org-ids>',
         'On board status': '/marketing/onboard/status',
         'Delayed scheduled rebuild task': 'add:/marketing/cache/rebuild/operation?opt=add&org-ids=<org-ids> '
                                           'delete:/marketing/cache/rebuild/operation?opt=delete&org-ids=<org-ids>',
         'Delayed task status': '/marketing/cache/rebuild/status?org-id=<org-ids>'
         })

def start():
    app.run(host='0.0.0.0', port=9080)
