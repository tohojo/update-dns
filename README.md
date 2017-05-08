# A small dynamic DNS update client

This is a small client for doing dynamic DNS updates (like nsupdate)
that is easier to use from the command line for one-off record updating.
It will try to discover the zone to update by querying for a SOA record,
then send an update for that zone.

To build:
```
go get
go build
```

To use, first create a config file at `~/.update-dns/update-dns.yaml`
(adjusting as needed for your setup):

```yaml
server: ns.example.org:53
tsig-secret: MyTsigSecret
tsig-name: updclient.example.org.
```

The, use it as follows:

To replace a record (will remove all records of the given type and
insert a new one):

`update-dns test.example.org 300 A 127.0.0.1`

To add a record without removing existing ones:

`update-dns -a test.example.org 300 A 127.0.0.1`

To delete a record type:

`update-dns -d test.example.org 300 A 127.0.0.1`

To delete a name entirely:

`update-dns -d test.example.org`
