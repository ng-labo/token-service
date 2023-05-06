# token-service
A example of Tornado application, service-api, data-store and oauth2 authentication.

This program just is written as study and demonstration.
I beleave Tornado is best framework in such application.

- providing token for user who is logged in.
  - Users are autheticated by github oauth2. So oauth2 set-up is needed for this application in github as a resource owner.
- check its legal for inquired token by rest api.
- use sqlite3 forpermanent datastore.

### requirement
- tornado 6.x
- sqlite3
- pycurl

### how to run and use?

- get client-id, client-secret by setting up your github oauth2 application.
- edit configs/token-service.yaml
- `python3 tokenservice/tornado/server.py --config=configs/token-service.yaml`

, and
- access to homepage in setting
- copy token string issued
- a example of use `curl https://token-service/query/<github-login>/?token=...`

### to study..
- consider token life cycle.
- data-store robustness and scale-out.
- make more api to be useful processing with token...
