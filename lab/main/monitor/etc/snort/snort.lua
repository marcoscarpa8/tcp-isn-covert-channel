HOME_NET = '10.0.1.0/24'
EXTERNAL_NET = '10.0.0.0/24'

default_variables =
{
    nets = { HOME_NET = HOME_NET, EXTERNAL_NET = EXTERNAL_NET },
    ports = { HTTP_PORTS = '80' },
}

-- Fix: Scapy-crafted packets have invalid checksums.
-- Without this, Snort silently drops them and no rules fire.
network =
{
    checksum_eval = 'none',
    checksum_drop = 'none',
}

stream = { }
stream_tcp = { }

ips = { variables = default_variables }

alert_fast = { file = false }
