# GeoIP (Phase 15)

Egress profiles can narrow their match to destinations in a specific
country. gmesh resolves ISO-3166 country codes to concrete CIDRs via an
operator-supplied CSV and installs them in an nftables named set.

## Config

```yaml
geoip:
  cidr_file: /etc/gmesh/geoip/cidrs.csv
```

Leave `cidr_file` empty to disable. Profiles with `geoip_countries` set
will then be rejected with a clear error — no silent "allow everything"
fallback.

## CSV format

One `country,cidr` line per entry. Blank lines and `#` comments
ignored.

```
# DB-IP lite export (CC-BY)
DE,5.0.0.0/8
DE,78.46.0.0/15
FR,2.0.0.0/12
US,8.8.8.0/24
```

Country codes are upper-cased; leading/trailing whitespace is trimmed.
Invalid CIDRs abort the load.

Common sources:

- **DB-IP lite**: https://db-ip.com/db/download/ip-to-country-lite
  (CC-BY — process into the above format with a few `awk` lines).
- **IPDeny**: http://www.ipdeny.com/ipblocks/ (one file per country
  already in CIDR form).
- **MaxMind GeoLite2 Country**: licence-gated; use your own account.

gmesh does not bundle a database — licences vary and operators often
want to pin a specific source.

## Egress profile field

```proto
repeated string geoip_countries = 10;
```

gRPC / gmeshctl:

```
gmeshctl egress create --id 5 --name de-only \
    --exit-peer 3 --protocol tcp --dest-ports 443 \
    --geoip-country DE --geoip-country AT
```

At create time the engine calls `geoip.Validate` — if any country is
unknown to the resolver the RPC returns InvalidArgument with the
offending code.

## nftables layout

Per profile, gmesh installs a set named `geoip_<profile_id>` inside
`inet gmesh-egress`:

```
set geoip_5 { type ipv4_addr; flags interval; elements = { 5.0.0.0/8, 78.46.0.0/15 } }
```

The per-profile mark rule adds `ip daddr @geoip_<id>` to the matcher so
only packets destined to DE/AT traffic get routed via the exit peer.
On delete, the set is removed in the same kernel transaction as the
rest of the profile's rules.

## Refresh

The CSV is loaded once at daemon startup. To pick up a fresh file:
1. Replace the CSV on disk atomically (`mv new.csv cidrs.csv`).
2. Restart gmeshd, or wait for a future `gmeshctl geoip reload` RPC
   (not implemented yet).

Egress profiles that were active at restart are re-created with the
refreshed CIDRs as part of normal state rehydration.
