# garytables

## Gary's interface to iptables

Inspired by [rfw](https://github.com/samrussell/rfw), this provides a RESTful interface to iptables

## Security stuff

- This runs as root, and is untested/unsafe code. Use at your own risk
- The HTTP auth username/password is hardcoded as admin:secret
- This opens port 8080 to the world and lets them change your iptables (or other stuff, if they find vulnerabilities here)
- HTTPS is not yet enabled - all data is sent in the clear

With the above in mind, don't use this in production. If you have a secure tunnel to whatever you're using (Flask can do wsgi so you can totally sit this behind Apache2/Nginx) then *maaaaaaaybe* have a play, but this app is really not yet safe or secure. Consider yourself warned.

## Usage/getting started

Starting garytables

```
> sudo ./garytables.py
```

Getting a list of tables:

```
> curl --user admin:secret -i -X GET http://localhost:8080/api/v1.0/table
```

```
HTTP/1.0 200 OK
Content-Type: application/json
Content-Length: 137
Server: Werkzeug/0.10.4 Python/2.7.6
Date: Mon, 14 Sep 2015 00:00:41 GMT

{
  "tables": [
    {
      "table_name": "filter",
      "url": "/api/v1.0/table/filter/chain"
    }
  ],
  "url": "/api/v1.0/table"
}
```

Getting a list of chains in a table

```
> curl --user admin:secret -i -X GET http://localhost:8080/api/v1.0/table/filter/chain
```

```
HTTP/1.0 200 OK
Content-Type: application/json
Content-Length: 457
Server: Werkzeug/0.10.4 Python/2.7.6
Date: Mon, 14 Sep 2015 00:01:51 GMT

{
  "chains": [
    {
      "chain_name": "input",
      "table_name": "filter",
      "url": "/api/v1.0/table/filter/chain/input/rule"
    },
    {
      "chain_name": "output",
      "table_name": "filter",
      "url": "/api/v1.0/table/filter/chain/output/rule"
    },
    {
      "chain_name": "forward",
      "table_name": "filter",
      "url": "/api/v1.0/table/filter/chain/forward/rule"
    }
  ],
  "url": "/api/v1.0/table/filter/chain"
}
```

Getting a list of rules in a chain

```
> curl --user admin:secret -i -X GET http://localhost:8080/api/v1.0/table/filter/chain/input/rule
```

```
HTTP/1.0 200 OK
Content-Type: application/json
Content-Length: 3122
Server: Werkzeug/0.10.4 Python/2.7.6
Date: Mon, 14 Sep 2015 00:03:36 GMT

{
  "rules": [
    {
      "chain_name": "input",
      "data": {
        "dst": "0.0.0.0/0.0.0.0",
        "protocol": "ip",
        "rule_num": 1,
        "src": "3.3.4.4/255.255.255.255",
        "target": "DROP"
      },
      "rule_num": 1,
      "table_name": "filter",
      "url": "/api/v1.0/table/filter/chain/input/rule/1"
    },
    {
      "chain_name": "input",
      "data": {
        "dst": "0.0.0.0/0.0.0.0",
        "protocol": "ip",
        "rule_num": 2,
        "src": "15.2.3.0/255.255.255.0",
        "target": "ACCEPT"
      },
      "rule_num": 2,
      "table_name": "filter",
      "url": "/api/v1.0/table/filter/chain/input/rule/2"
    }
  ],
  "url": "/api/v1.0/table/filter/chain/input/rule"
```

Inserting a rule

```
> curl --user admin:secret -i -H "Content-Type: application/json" -X POST -d '{"src":"3.3.4.6/255.255.255.255", "target":"DROP"}' http://localhost:8080/api/v1.0/table/filter/chain/input/rule
```

```
HTTP/1.0 200 OK
Content-Type: application/json
Content-Length: 279
ETag: 3261b49bf9877992c1d832d946f16d3679cc3209ecae7e7d64ced62753b6986c
Server: Werkzeug/0.10.4 Python/2.7.6
Date: Mon, 14 Sep 2015 00:05:20 GMT

{
  "chain_name": "input",
  "data": {
    "dst": "0.0.0.0/0.0.0.0",
    "protocol": "ip",
    "rule_num": 1,
    "src": "3.3.4.6/255.255.255.255",
    "target": "DROP"
  },
  "rule_num": 1,
  "table_name": "filter",
  "url": "/api/v1.0/table/filter/chain/input/rule/1"
}
```

Getting a rule

```
> curl --user admin:secret -i -X GET http://localhost:8080/api/v1.0/table/filter/chain/input/rule/1
```

```
HTTP/1.0 200 OK
Content-Type: application/json
Content-Length: 279
ETag: 3261b49bf9877992c1d832d946f16d3679cc3209ecae7e7d64ced62753b6986c
Server: Werkzeug/0.10.4 Python/2.7.6
Date: Mon, 14 Sep 2015 00:06:14 GMT

{
  "chain_name": "input",
  "data": {
    "dst": "0.0.0.0/0.0.0.0",
    "protocol": "ip",
    "rule_num": 1,
    "src": "3.3.4.6/255.255.255.255",
    "target": "DROP"
  },
  "rule_num": 1,
  "table_name": "filter",
  "url": "/api/v1.0/table/filter/chain/input/rule/1"
}
```

Deleting a rule

```
# Note the "ETag" returned when adding/querying a rule - this needs to be passed to the DELETE command or it fails
> curl --user admin:secret -i -H "ETag: 3261b49bf9877992c1d832d946f16d3679cc3209ecae7e7d64ced62753b6986c" -X DELETE http://localhost:8080/api/v1.0/table/filter/chain/input/rule/1
```

```
HTTP/1.0 204 NO CONTENT
Content-Type: text/html; charset=utf-8
Content-Length: 0
Server: Werkzeug/0.10.4 Python/2.7.6
Date: Mon, 14 Sep 2015 00:07:36 GMT
```

