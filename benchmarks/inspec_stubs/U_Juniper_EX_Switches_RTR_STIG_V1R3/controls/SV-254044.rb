control 'SV-254044' do
  title 'The Juniper BGP router must be configured to enable the Generalized TTL Security Mechanism (GTSM).'
  desc "GTSM is designed to protect a router's IP-based control plane from DoS attacks. Many attacks focused on CPU load and line-card overload can be prevented by implementing GTSM on all Exterior Border Gateway Protocol speaking routers. 

GTSM is based on the fact that the vast majority of control plane peering is established between adjacent routers; that is, the Exterior Border Gateway Protocol peers are either between connecting interfaces or between loopback interfaces. Since TTL spoofing is considered nearly impossible, a mechanism based on an expected TTL value provides a simple and reasonably robust defense from infrastructure attacks based on forged control plane traffic."
  desc 'check', 'Review the router configuration. Verify a firewall filter term discards BGP packets with a TTL less than 255.
[edit firewall family inet]
filter gtsm {
    term 1 {
        from {
            protocol tcp;
            ttl 255;
            destination-port bgp;
        }
        then accept;
    }
    term 2 {
        from {
            protocol tcp;
            destination-port bgp;
        }
        then {
            log;
            syslog;
            discard;
        }
    }
    <additional accept terms>
    term default {
        then {
            log;
            syslog;
            discard;
        }
    }
}

Some routers support the "ttl-except" directive that can replace the two term filter shown above. For example:
[edit firewall family inet]
filter gtsm {
    term 1 {
        from {
            protocol tcp;
            ttl-except 255;
            destination-port bgp;
        }
        then {
            log;
            syslog;
            discard;
        }
    }
    <additional accept terms>
    term default {
        then {
            log;
            syslog;
            discard;
        }
    }
}

Verify the filter is applied to BGP neighbor interfaces.
[edit interfaces]
<bgp interface> {
    unit <number> {
        family inet {
            filter input gtsm;
        }
        address <IPv4 address>.<mask>;
    }
}

Note: Some Juniper devices support both monolithic filters and filter lists. Filter lists separate each term, or set of terms, into a separate filter that is applied sequentially to an interface. If using filter lists, the keywords "input" or "output" change to "input-list" or "output-list". Verify the final list item is a deny-all filter. The deny-all filter is created once per family and can be reused across multiple lists. For example:

input-list [ permit_mgt permit_routing_protocols default-deny ];

If the router is not configured to use GTSM for all Exterior Border Gateway Protocol peering sessions, this is a finding.'
  desc 'fix', "Configure all Exterior Border Gateway Protocol peering sessions to use GTSM.

set firewall family inet filter gtsm term 1 from protocol tcp
set firewall family inet filter gtsm term 1 from ttl 255
set firewall family inet filter gtsm term 1 from destination-port bgp
set firewall family inet filter gtsm term 1 then accept
set firewall family inet filter gtsm term 2 from protocol tcp
set firewall family inet filter gtsm term 2 from destination-port bgp
set firewall family inet filter gtsm term 2 then log
set firewall family inet filter gtsm term 2 then syslog
set firewall family inet filter gtsm term 2 then discard
<additional accept terms>
set firewall family inet filter gtsm term default then log
set firewall family inet filter gtsm term default then syslog
set firewall family inet filter gtsm term default then discard

For those platforms that support 'ttl-except':
set firewall family inet filter gtsm term 1 from protocol tcp
set firewall family inet filter gtsm term 1 from ttl-except 255
set firewall family inet filter gtsm term 1 from destination-port bgp
set firewall family inet filter gtsm term 1 then log
set firewall family inet filter gtsm term 1 then syslog
set firewall family inet filter gtsm term 1 then discard
<additional accept terms>
set firewall family inet filter gtsm term default then log
set firewall family inet filter gtsm term default then syslog
set firewall family inet filter gtsm term default then discard

set interfaces <BGP interface> unit <number> family inet filter input gtsm
set interfaces <BGP interface> unit <number> family inet address <IPv4 address>.<mask>"
  impact 0.3
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57496r844163_chk'
  tag severity: 'low'
  tag gid: 'V-254044'
  tag rid: 'SV-254044r844165_rule'
  tag stig_id: 'JUEX-RT-000720'
  tag gtitle: 'SRG-NET-000362-RTR-000124'
  tag fix_id: 'F-57447r844164_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
