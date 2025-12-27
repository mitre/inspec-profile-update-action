control 'SV-256034' do
  title 'The Arista router must be configured to have Internet Control Message Protocol (ICMP) redirects disabled on all external interfaces.'
  desc 'The ICMP supports IP traffic by relaying information about paths, routes, and network conditions. Routers automatically send ICMP messages under a wide variety of conditions. Redirect ICMP messages are commonly used by attackers for network mapping and diagnosis.'
  desc 'check', 'Review the device configuration to determine if controls have been defined to ensure the router does not send ICMP Redirect messages out to any external interfaces.

Step 1: To verify the ACL is configured to determine the router does not send ICMP Redirect messages out to any external interfaces, execute the command "sh ip access-list".

ip access-group DENY_REDIRECT
 deny icmp any any redirect
 permit ip any any

Step 2: To verify the ACL is applied outbound on interface, execute the command "sh run int Eth YY".

interface Ethernet 2
 ip access-group DENY_REDIRECT out

If ICMP Redirect messages are enabled on any external interfaces, this is a finding.'
  desc 'fix', 'Step 1: Disable ICMP redirects on all external interfaces.

ip access-group DENY_REDIRECT
 deny icmp any any redirect
 permit ip any any

Step 2: Apply the ACL outbound on interfaces.

interface Ethernet 2
description EXTERNAL INTERFACE
 ip access-group DENY_REDIRECT in'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59710r882442_chk'
  tag severity: 'medium'
  tag gid: 'V-256034'
  tag rid: 'SV-256034r882444_rule'
  tag stig_id: 'ARST-RT-000550'
  tag gtitle: 'SRG-NET-000362-RTR-000115'
  tag fix_id: 'F-59653r882443_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
