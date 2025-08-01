control 'SV-217051' do
  title 'The Juniper BGP router must be configured to enable the Generalized TTL Security Mechanism (GTSM).'
  desc "GTSM is designed to protect a router's IP-based control plane from DoS attacks. Many attacks focused on CPU load and line-card overload can be prevented by implementing GTSM on all Exterior Border Gateway Protocol speaking routers. 

GTSM is based on the fact that the vast majority of control plane peering is established between adjacent routers; that is, the Exterior Border Gateway Protocol peers are either between connecting interfaces or between loopback interfaces. Since TTL spoofing is considered nearly impossible, a mechanism based on an expected TTL value provides a simple and reasonably robust defense from infrastructure attacks based on forged control plane traffic."
  desc 'check', 'Verify that a filter has been configured to only allow BGP packets with a TTL of 255 as shown in the example below.

firewall {
        …
        …
        …
    filter GTSM_FILTER {
        term TTL_SECURITY {
            from {
                protocol tcp;
                ttl-except 255;
                port bgp;
            }
            then {
                syslog;
                discard;
            }
        }
        term ELSE_ACCEPT {
            then accept;
        }
    }
}

Verify that the filter is applied to all interfaces connecting to eBGP peers.

interfaces {
…
…
…
  ge-0/0/0  {
        unit 0 {
            family inet {
                filter {
                    input-list [INBOUND_FILTER GTSM_FILTER];
                }
                address x.x.x.x/30;
            }
         }
    }
}

Configure the router to send all BGP packets with a TTL of 255 as shown in the example below.

If the router is not configured to use GTSM for all Exterior Border Gateway Protocol peering sessions, this is a finding.'
  desc 'fix', 'Configure a filter to only accept bgp packets with a TTL of 255 as shown in the example below.

[edit firewall]
set filter GTSM_FILTER term TTL_SECURITY from protocol tcp port bgp ttl-except 255
set filter GTSM_FILTER term TTL_SECURITY then syslog discard
set filter GTSM_FILTER term ELSE_ACCEPT then accept

Apply the firewall filter to the inbound interface for all eBGP single-hop peer as shown in the example below.

[edit interfaces   ge-0/0/0  unit 0 family inet] 
set filter input-list INBOUND_FILTER
set filter input-list GTSM_FILTER'
  impact 0.3
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18280r297021_chk'
  tag severity: 'low'
  tag gid: 'V-217051'
  tag rid: 'SV-217051r604135_rule'
  tag stig_id: 'JUNI-RT-000460'
  tag gtitle: 'SRG-NET-000362-RTR-000124'
  tag fix_id: 'F-18278r297022_fix'
  tag 'documentable'
  tag legacy: ['SV-101097', 'V-90887']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
