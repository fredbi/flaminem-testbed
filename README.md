# Demo: keycloak OIDC federations w/ role claims

### Problem description

The issue is well described by keycloak [issue #KEYCLOAK-8690](https://issues.jboss.org/browse/KEYCLOAK-8690)
and [issue #KEYCLOAK-7142](https://issues.jboss.org/browse/KEYCLOAK-7142).

This problem deals with automatically binding claims presented by some federated user to keycloak roles
when updating an already provisioned user.

1. Role mapping when user first connects: OK, the user is created with the correct mapped roles
2. Role mapping when user reconnects, with a different set of claims to map: 
  * whenever a role has to be removed, OK
  * **whenever a role has to be added: KO, role mappings are not updated**

This applies to federated identities mapped through a standard OIDC broker
as well as through a keycloak OIDC broker (the only difference between these is 
that "federated roles" are natively parsed from the token using the structure of the keycloak token).

### Fix

The fix is very lightweight but touches core classes for OIDC identity broker (in `services/src/main/java/org/keycloak/broker/oidc`).

It is based on `https://github.com/keycloak/keycloak@7.0.0` (latest buildable release).

The fix is available at `https://github.com/fredbi/keycloak`, branch: `fix-8690-flaminem`.

The fix does not affect "social login" brokers, nor does it change the behavior of SAML or LDAP federated identifies.

Disclaimer: depending on your dev env, you might want to omit the initial commit on the typescript source (i.e. admin console UI app).
There is no actual code change but line feeds. I just found this omission much of an annoyance when developping on a unix system.

### Extra

* added unit test with new dependency on mockito mocking package
* added logging all grant/revoke actions on brokered users, e.g.

```
07:22:16,565 INFO  [org.keycloak.broker.oidc.mappers.ClaimToRoleMapper] (default task-4) granting role can-do-that to brokered user: frederic-oidc
```

### Demonstration

##### Build demo

Build docker images: there is a builder to save a litle time next time you build, then the main image.

> Disclaimer: for the sake of this demonstration I've kept the Dockerfile simple and compatible with most docker versions running around.
> It is almost directly copied from the official keycloak repo to build docker images: `https://github.com/keycloak/keycloak-containers`.
> As a consequence the build is pretty crude, in particular when it comes to download maven dependencies (on my dev env, it takes more than 1h...).

```bash
hack/build-all-images.sh
```

```bash
docker images|grep keycloak
...
keycloak-flaminem                                               latest                            5e35fd54be45        7 minutes ago       1.22GB
keycloak-builder                                                latest                            91e39cf04dd9        28 hours ago        910MB
jboss/keycloak                                                  6.0.1                             3a6718ca4ee0        5 months ago        1.2GB
```

##### Run demo

Launch the `docker-compose` ensemble:

```bash 
docker-compose up --detach postgres 
docker-compose logs -f postgres 
```

You should see postgres starting and restoring the required databases from the dump located at `./hack/dbseed/keycloak-20190909.sql`.

There are 3 keycloak databases hosted by this postgres instance.

When this is done, you can start the various keycloak instances:

```bash
docker-compose up --detach
```

You may follow-up the startup stage:
```bash
docker-compose logs -f keycloak-flaminem.localtest.me
```

There are 3 keycloak instances. They all resolve automatically to your local host (`.localtest.me`) with http.

2 instances (v6.0.0) simulate remote identity providers managed by customers and 1 simulate the flaminem IDP. Only the latter requires patching.

Two instances are needed to assert 2 different use cases: one declared as standard OIDC allows for checking generic claim to role mappers. The other, declared as a 
remote keycloak, allows for checking "External role" mapper.

We tried to keep the configuration of these 3 instances minimal: realm is only master and the app to connect is simply the admin console.

### Play book

You can take a quick tour of the testbed configuration (7 min): [here](https://raw.githubusercontent.com/fredbi/flaminem-testbed/master/docs/config.mp4).

You may follow a full testcase (5 min) [here](https://raw.githubusercontent.com/fredbi/flaminem-testbed/master/docs/demo.mp4) to verify that roles are correctly updated, or play by yourself with this docker-compose testbed.

URLs and credentials:

* `http://keycloak-flaminem.localtest.me:8080`   -- admin/flaminem : flaminem IDP
* `http://keycloak-customer.localtest.me:8081`   -- admin/customer : federated identity provider, declared as standard OIDC
                                                    user: frederic-keycloak/frederic-keycloak
* `http://keycloak-oidc.localtest.me:8082`       -- admin/oidc : federated identity provider, declared as keycloak IDP
                                                    user: frederic-oidc/frederic-oidc



##### Scratching & rebuilding the demo

This cleans up volumes and containers, but keep your images:

```bash 
hack/docker-clean.sh
```
