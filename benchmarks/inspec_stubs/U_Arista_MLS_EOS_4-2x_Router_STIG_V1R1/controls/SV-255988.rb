control 'SV-255988' do
  title 'The Arista BGP router must be configured to reject inbound route advertisements for any Bogon prefixes.'
  desc 'Accepting route advertisements for bogon prefixes can result in the local autonomous system (AS) becoming a transit for malicious traffic as it will in turn advertise these prefixes to neighbor autonomous systems.'
  desc 'check', 'Review the Arista router configuration to verify it will reject routes of any Bogon prefixes.

The prefix filter must be referenced inbound on the appropriate BGP neighbor statements.

Step 1: Review the BGP Bogon Prefix Lists configured. To verify IP prefix lists are configured, execute the command "show ip prefix-list".

ip prefix-list BOGON_v4
  seq 1 deny 0.0.0.0/8 le 32
  seq 2 deny 10.0.0.0/8 le 32
  seq 3 deny 100.64.0.0/10 le 32
  seq 4 deny 127.0.0.0/8 le 32
  seq 5 deny 169.254.0.0/16 le 32
  seq 6 deny 172.16.0.0/12 le 32
  seq 100 permit 0.0.0.0/0 ge 8

Step 2: Review the prefix lists inbound to the appropriate BGP neighbor to verify the BGP config and verify the prefix is applied. Execute the command "show ip bgp nei X.2.1.1".

router bgp 65001     
  neighbor 100.2.1.1 prefix-list BOGON_v4 in

If the Arista router is not configured to reject or permit inbound route advertisements for any bogon prefixes, this is a finding.'
  desc 'fix', 'Step 1: Configure the BGP Bogon Prefix List.

LEAF-1A(config)#ip prefix-list BOGON_v4
LEAF-1A(config-ip-pfx)#seq 1 deny 0.0.0.0/8 le 32
LEAF-1A(config-ip-pfx)#seq 2 deny 10.0.0.0/8 le 32
LEAF-1A(config-ip-pfx)#seq 3 deny 100.64.0.0/10 le 32
LEAF-1A(config-ip-pfx)#seq 4 deny 127.0.0.0/8 le 32
LEAF-1A(config-ip-pfx)#seq 5 deny 169.254.0.0/16 le 32
LEAF-1A(config-ip-pfx)#seq 6 deny 172.16.0.0/12 le 32
LEAF-1A(config-ip-pfx)#seq 100 permit 0.0.0.0/0 ge 8

Step 2: Configure the prefix list inbound to the appropriate BGP neighbor.

LEAF-1A(config)#router bgp 65001     
LEAF-1A(config-router-bgp)#neighbor 100.2.1.1 prefix-list BOGON_v4 in'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59664r882304_chk'
  tag severity: 'medium'
  tag gid: 'V-255988'
  tag rid: 'SV-255988r882306_rule'
  tag stig_id: 'ARST-RT-000020'
  tag gtitle: 'SRG-NET-000018-RTR-000002'
  tag fix_id: 'F-59607r882305_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
