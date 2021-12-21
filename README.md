# sample-subnetpool-server

This tool aims to confirm how subnetpool mechanism on neutron-server works
And then, we can learn how to create subnet with allocated cidr using subnetpool

## How to Run

Starting sample subnetpool program as following

    $ python sample_subnetpool_server.py
    Bottle v0.12.19 server starting up (using WSGIRefServer())...
    Listening on http://0.0.0.0:8081/
    Hit Ctrl-C to quit.

## (1) How to create subnet with allocated cidr for addressing IPv4

### (1-1) How to create subnetpool for IPv4

First of all, you need to create subnetpool

    $ curl -X POST http://127.0.0.1:8081/subnetpools \
    > -H "Content-Type: application/json" \
    > -d @- << EOF | jq .
    > {
    >   "subnetpool": {
    >     "default_prefixlen": 26,
    >     "name": "subnetpool-ipv4-1",
    >     "prefixes": [
    >       "203.0.113.0/24"
    >     ]
    >   }
    > }
    > EOF
    {
      "subnetpool": {
        "prefixes": [
          "203.0.113.0/24"
        ],
        "min_prefixlen": 8,
        "name": "subnetpool-ipv4-1",
        "ip_version": 4,
        "default_prefixlen": 26,
        "project_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "id": "b4c2a011-0c27-42f2-b47d-e7d30ff77d08",
        "max_prefixlen": 32
      }
    }

If you want to allocate another prefix range, please modify prefixes property

    $ curl -X PUT http://127.0.0.1:8081/subnetpools/b4c2a011-0c27-42f2-b47d-e7d30ff77d08 \
    > -H "Content-Type: application/json" \
    > -d @- << EOF | jq .
    > {
    >   "subnetpool": {
    >     "prefixes": [
    >       "203.0.113.0/24", "192.0.2.0/24"
    >     ]
    >   }
    > }
    > EOF
    {
      "subnetpool": {
        "prefixes": [
          "203.0.113.0/24",
          "192.0.2.0/24"
        ],
        "min_prefixlen": 8,
        "name": "subnetpool-ipv4-1",
        "ip_version": 4,
        "default_prefixlen": 26,
        "project_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "id": "b4c2a011-0c27-42f2-b47d-e7d30ff77d08",
        "max_prefixlen": 32
      }
    }

And then, you can confirm current subnetpools

    $ curl -X GET http://127.0.0.1:8081/subnetpools | jq .
    {
      "subnetpools": [
        {
          "prefixes": [
            "203.0.113.0/24",
            "192.0.2.0/24"
          ],
          "min_prefixlen": 8,
          "name": "subnetpool-ipv4-1",
          "ip_version": 4,
          "default_prefixlen": 26,
          "project_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "id": "b4c2a011-0c27-42f2-b47d-e7d30ff77d08",
          "max_prefixlen": 32
        }
      ]
    }

### (1-2) How to create subnet using subnetpool for IPv4

Let's create some subnets
Firstly, if you want to create subnet with allocated cidr, you can handle it

    $ curl -X POST http://127.0.0.1:8081/subnets \
    > -H "Content-Type: application/json" \
    > -d @- << EOF | jq .
    > {
    >   "subnet": {
    >     "ip_version": 4,
    >     "name": "subnet-ipv4-1",
    >     "network_id": "11111111-1111-1111-1111-111111111111",
    >     "subnetpool_id": "b4c2a011-0c27-42f2-b47d-e7d30ff77d08"
    >   }
    > }
    > EOF
    {
      "subnet": {
        "name": "subnet-ipv4-1",
        "network_id": "11111111-1111-1111-1111-111111111111",
        "ip_version": 4,
        "cidr": "192.0.2.0/26",
        "project_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "id": "47703eac-1ff8-4826-8250-9d484d651ea6",
        "subnetpool_id": "b4c2a011-0c27-42f2-b47d-e7d30ff77d08"
      }
    }

Secondly, try it again

    $ curl -X POST http://127.0.0.1:8081/subnets \
    > -H "Content-Type: application/json" \
    > -d @- << EOF | jq .
    > {
    >   "subnet": {
    >     "ip_version": 4,
    >     "name": "subnet-ipv4-2",
    >     "network_id": "11111111-1111-1111-1111-111111111111",
    >     "subnetpool_id": "b4c2a011-0c27-42f2-b47d-e7d30ff77d08"
    >   }
    > }
    > EOF
    {
      "subnet": {
        "name": "subnet-ipv4-2",
        "network_id": "11111111-1111-1111-1111-111111111111",
        "ip_version": 4,
        "cidr": "192.0.2.64/26",
        "project_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "id": "47703eac-1ff8-4826-8250-9d484d651ea6",
        "subnetpool_id": "b4c2a011-0c27-42f2-b47d-e7d30ff77d08"
      }
    }

Thirdly, try it more

    $ curl -X POST http://127.0.0.1:8081/subnets \
    > -H "Content-Type: application/json" \
    > -d @- << EOF | jq .
    > {
    >   "subnet": {
    >     "ip_version": 4,
    >     "name": "subnet-ipv4-3",
    >     "network_id": "11111111-1111-1111-1111-111111111111",
    >     "subnetpool_id": "b4c2a011-0c27-42f2-b47d-e7d30ff77d08"
    >   }
    > }
    > EOF
    {
      "subnet": {
        "name": "subnet-ipv4-3",
        "network_id": "11111111-1111-1111-1111-111111111111",
        "ip_version": 4,
        "cidr": "192.0.2.128/26",
        "project_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "id": "47703eac-1ff8-4826-8250-9d484d651ea6",
        "subnetpool_id": "b4c2a011-0c27-42f2-b47d-e7d30ff77d08"
      }
    }

Fourthly, try it more

    $ curl -X POST http://127.0.0.1:8081/subnets \
    > -H "Content-Type: application/json" \
    > -d @- << EOF | jq .
    > {
    >   "subnet": {
    >     "ip_version": 4,
    >     "name": "subnet-ipv4-4",
    >     "network_id": "11111111-1111-1111-1111-111111111111",
    >     "subnetpool_id": "b4c2a011-0c27-42f2-b47d-e7d30ff77d08"
    >   }
    > }
    > EOF
    {
      "subnet": {
        "name": "subnet-ipv4-4",
        "network_id": "11111111-1111-1111-1111-111111111111",
        "ip_version": 4,
        "cidr": "192.0.2.192/26",
        "project_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "id": "47703eac-1ff8-4826-8250-9d484d651ea6",
        "subnetpool_id": "b4c2a011-0c27-42f2-b47d-e7d30ff77d08"
      }
    }

And then, you can confirm current subnets

    $ curl -X GET http://127.0.0.1:8081/subnets | jq .
    {
      "subnets": [
        {
          "name": "subnet-ipv4-2",
          "network_id": "11111111-1111-1111-1111-111111111111",
          "ip_version": 4,
          "cidr": "192.0.2.64/26",
          "project_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "id": "0e55b14d-1c31-4947-8a9d-94b904c99881",
          "subnetpool_id": "b4c2a011-0c27-42f2-b47d-e7d30ff77d08"
        },
        {
          "name": "subnet-ipv4-1",
          "network_id": "11111111-1111-1111-1111-111111111111",
          "ip_version": 4,
          "cidr": "192.0.2.0/26",
          "project_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "id": "47703eac-1ff8-4826-8250-9d484d651ea6",
          "subnetpool_id": "b4c2a011-0c27-42f2-b47d-e7d30ff77d08"
        },
        {
          "name": "subnet-ipv4-3",
          "network_id": "11111111-1111-1111-1111-111111111111",
          "ip_version": 4,
          "cidr": "192.0.2.128/26",
          "project_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "id": "740005a4-0db5-4fa8-97db-814e4e209df7",
          "subnetpool_id": "b4c2a011-0c27-42f2-b47d-e7d30ff77d08"
        },
        {
          "name": "subnet-ipv4-4",
          "network_id": "11111111-1111-1111-1111-111111111111",
          "ip_version": 4,
          "cidr": "192.0.2.192/26",
          "project_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "id": "94e51e4e-408e-4ba3-93c3-c6160c4243cc",
          "subnetpool_id": "b4c2a011-0c27-42f2-b47d-e7d30ff77d08"
        }
      ]
    }

As you see, it doesn't look to have vacant prefix pool in "192.0.2.0/24"
Anyway, let's try to create subnet

    $ curl -X POST http://127.0.0.1:8081/subnets \
    > -H "Content-Type: application/json" \
    > -d @- << EOF | jq .
    > {
    >   "subnet": {
    >     "ip_version": 4,
    >     "name": "subnet-ipv4-5",
    >     "network_id": "11111111-1111-1111-1111-111111111111",
    >     "subnetpool_id": "b4c2a011-0c27-42f2-b47d-e7d30ff77d08"
    >   }
    > }
    > EOF
    {
      "subnet": {
        "name": "subnet-ipv4-5",
        "network_id": "11111111-1111-1111-1111-111111111111",
        "ip_version": 4,
        "cidr": "203.0.113.0/26",
        "project_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "id": "47703eac-1ff8-4826-8250-9d484d651ea6",
        "subnetpool_id": "b4c2a011-0c27-42f2-b47d-e7d30ff77d08"
      }
    }

It succeeded to create subnet with allocated cidr as "203.0.113.0/26"


## (2) How to create subnet with allocated cidr for addressing IPv6

### (2-1) How to create subnetpool for IPv6

First of all, you need to create subnetpool

    $ curl -X POST http://127.0.0.1:8081/subnetpools \
    > -H "Content-Type: application/json" \
    > -d @- << EOF | jq .
    > {
    >   "subnetpool": {
    >     "default_prefixlen": 64,
    >     "max_prefixlen": 64,
    >     "min_prefixlen": 64,
    >     "name": "subnetpool-ipv6-1",
    >     "prefixes": [
    >       "2001:DB8:1111::/48"
    >     ]
    >   }
    > }
    > EOF
    {
      "subnetpool": {
        "prefixes": [
          "2001:db8:1111::/48"
        ],
        "min_prefixlen": 64,
        "name": "subnetpool-ipv6-1",
        "ip_version": 6,
        "default_prefixlen": 64,
        "project_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "id": "ec7356fa-fa6c-401d-ac90-498b3d775409",
        "max_prefixlen": 64
      }
    }

### (2-2) How to create subnet using subnetpool for IPv6

Let's create some subnets
Firstly, if you want to create subnet with allocated cidr, you can handle it

    $ curl -X POST http://127.0.0.1:8081/subnets \
    > -H "Content-Type: application/json" \
    > -d @- << EOF | jq .
    > {
    >   "subnet": {
    >     "ip_version": 6,
    >     "ipv6_address_mode": "dhcpv6-stateful",
    >     "ipv6_ra_mode": "dhcpv6-stateful",
    >     "name": "subnet-ipv6-1",
    >     "network_id": "22222222-2222-2222-2222-222222222222",
    >     "subnetpool_id": "ec7356fa-fa6c-401d-ac90-498b3d775409"
    >   }
    > }
    > EOF
    {
      "subnet": {
        "name": "subnet-ipv6-1",
        "network_id": "22222222-2222-2222-2222-222222222222",
        "ip_version": 6,
        "cidr": "2001:db8:1111::/64",
        "project_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "id": "3b27435a-a6de-401d-9dba-1e99222d67d5",
        "subnetpool_id": "ec7356fa-fa6c-401d-ac90-498b3d775409"
      }
    }

Secondly, try it again

    $ curl -X POST http://127.0.0.1:8081/subnets \
    > -H "Content-Type: application/json" \
    > -d @- << EOF | jq .
    > {
    >   "subnet": {
    >     "ip_version": 6,
    >     "ipv6_address_mode": "dhcpv6-stateful",
    >     "ipv6_ra_mode": "dhcpv6-stateful",
    >     "name": "subnet-ipv6-2",
    >     "network_id": "22222222-2222-2222-2222-222222222222",
    >     "subnetpool_id": "ec7356fa-fa6c-401d-ac90-498b3d775409"
    >   }
    > }
    > EOF
    {
      "subnet": {
        "name": "subnet-ipv6-2",
        "network_id": "22222222-2222-2222-2222-222222222222",
        "ip_version": 6,
        "cidr": "2001:db8:1111:1::/64",
        "project_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "id": "3b27435a-a6de-401d-9dba-1e99222d67d5",
        "subnetpool_id": "ec7356fa-fa6c-401d-ac90-498b3d775409"
      }
    }

Thirdly, try it more

    $ curl -X POST http://127.0.0.1:8081/subnets \
    > -H "Content-Type: application/json" \
    > -d @- << EOF | jq .
    > {
    >   "subnet": {
    >     "ip_version": 6,
    >     "ipv6_address_mode": "dhcpv6-stateful",
    >     "ipv6_ra_mode": "dhcpv6-stateful",
    >     "name": "subnet-ipv6-3",
    >     "network_id": "22222222-2222-2222-2222-222222222222",
    >     "subnetpool_id": "ec7356fa-fa6c-401d-ac90-498b3d775409"
    >   }
    > }
    > EOF
    {
      "subnet": {
        "name": "subnet-ipv6-3",
        "network_id": "22222222-2222-2222-2222-222222222222",
        "ip_version": 6,
        "cidr": "2001:db8:1111:2::/64",
        "project_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "id": "3b27435a-a6de-401d-9dba-1e99222d67d5",
        "subnetpool_id": "ec7356fa-fa6c-401d-ac90-498b3d775409"
      }
    }

Fourthly, try it more

    $ curl -X POST http://127.0.0.1:8081/subnets \
    > -H "Content-Type: application/json" \
    > -d @- << EOF | jq .
    > {
    >   "subnet": {
    >     "ip_version": 6,
    >     "ipv6_address_mode": "dhcpv6-stateful",
    >     "ipv6_ra_mode": "dhcpv6-stateful",
    >     "name": "subnet-ipv6-4",
    >     "network_id": "22222222-2222-2222-2222-222222222222",
    >     "subnetpool_id": "ec7356fa-fa6c-401d-ac90-498b3d775409"
    >   }
    > }
    > EOF
    {
      "subnet": {
        "name": "subnet-ipv6-4",
        "network_id": "22222222-2222-2222-2222-222222222222",
        "ip_version": 6,
        "cidr": "2001:db8:1111:3::/64",
        "project_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "id": "3b27435a-a6de-401d-9dba-1e99222d67d5",
        "subnetpool_id": "ec7356fa-fa6c-401d-ac90-498b3d775409"
      }
    }
