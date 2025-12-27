control 'SV-256033' do
  title 'The Arista router must be configured to have Internet Control Message Protocol (ICMP) mask replies disabled on all external interfaces.'
  desc 'The ICMP supports IP traffic by relaying information about paths, routes, and network conditions. Routers automatically send ICMP messages under a wide variety of conditions. Mask Reply ICMP messages are commonly used by attackers for network mapping and diagnosis.'
  desc 'check', 'Review the Arista device configuration to determine if controls have been defined to ensure the router does not send ICMP Mask Reply messages out to any external interfaces.

EOS by default does not respond to ICMP Type 17 or 18. 

Step 1: To verify the ACL is configured to determine the router does not send ICMP Mask Reply messages out to any external interfaces, execute the command "sh ip access-list".

ip access-group DENY_ICMP_MASK_REPLY
 deny icmp any any mask-reply
 permit ip any any

Step 2: To verify the ACL is applied outbound on interfaces, execute the command "sh run int Eth YY".

interface Ethernet 2
 ip access-group DENY_ICMP_MASK_REPLY out

If ICMP Mask Reply messages are enabled on any external interfaces, this is a finding.'
  desc 'fix', 'Step 1: Disable ICMP mask replies on all external interfaces.

ip access-group DENY_ICMP_MASK_REPLY
 deny icmp any any mask-reply
 permit ip any any

Step 2: Apply the ACL outbound on interfaces.

interface Ethernet 2
 ip access-group DENY_ICMP_MASK_REPLY out'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59709r882439_chk'
  tag severity: 'medium'
  tag gid: 'V-256033'
  tag rid: 'SV-256033r882441_rule'
  tag stig_id: 'ARST-RT-000540'
  tag gtitle: 'SRG-NET-000362-RTR-000114'
  tag fix_id: 'F-59652r882440_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
