control 'SV-239854' do
  title 'The Cisco ASA must be configured to restrict VPN traffic according to organization-defined filtering rules.'
  desc 'Remote access devices (such as those providing remote access to network devices and information systems) that lack automated capabilities increase risk and make remote user access management difficult at best.

Remote access is access to DoD non-public information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network.

Automated monitoring of remote access sessions allows organizations to detect cyberattacks and also ensure ongoing compliance with remote access policies by auditing connection activities of remote access capabilities from a variety of information system components (e.g., servers, workstations, notebook computers, smart phones, and tablets).'
  desc 'check', 'Step 1: Verify that an ACL has been applied to the applicable VPN group policy via the vpn-filter attribute as shown in the example below.

group-policy VPN_POLICY internal
group-policy VPN_POLICY attributes
 …
 …
 …
 vpn-filter value RESTRICT_VPN

Step 2: Verify that the filter restricts traffic according to organization-defined filtering rules as shown in the example below.

access-list RESTRICT_VPN extended permit tcp 10.0.0.0 255.255.255.0 host 192.168.1.12 eq http 
access-list RESTRICT_VPN extended permit tcp 10.0.0.0 255.255.255.0  host 192.168.1.13 eq smtp 
access-list RESTRICT_VPN extended permit tcp 10.0.0.0 255.255.255.0  host 192.168.1.14 eq ftp 
access-list RESTRICT_VPN extended permit tcp 10.0.0.0 255.255.255.0 host 192.168.1.14 eq ftp-data 
access-list RESTRICT_VPN extended permit tcp 10.0.0.0 255.255.255.0  host 192.168.1.15 eq domain
access-list RESTRICT_VPN extended permit tcp 10.0.0.0 255.255.255.0  host 192.168.1.16 eq sqlnet
access-list RESTRICT_VPN extended deny ip any any log

Note: In the example above, assume that the client-assigned IP address pool is 10.10.10.0/24 and the local private network is 192.168.1.0/24.

If the ASA is not configured to restrict VPN traffic according to organization-defined filtering rules, this is a finding.'
  desc 'fix', 'Step 1: Configure the ACL to restrict VPN traffic.

ASA(config)# access-list RESTRICT_VPN extended permit tcp 10.0.0.0 255.255.255. host 192.168.1.12 eq http
ASA(config)# access-list RESTRICT_VPN extended permit tcp 10.0.0.0 255.255.255. host 192.168.1.13 eq smtp
ASA(config)# access-list RESTRICT_VPN extended permit tcp 10.0.0.0 255.255.255. host 192.168.1.14 eq ftp
ASA(config)# access-list RESTRICT_VPN extended permit tcp 10.0.0.0 255.255.255. host 192.168.1.14 eq ftp-data
ASA(config)# access-list RESTRICT_VPN extended permit tcp 10.0.0.0 255.255.255.y host 192.168.1.15 eq domain
ASA(config)# access-list RESTRICT_VPN extended permit tcp 10.0.0.0 255.255.255. host 192.168.1.16 eq sqlnet
ASA(config)# access-list RESTRICT_VPN extended deny ip any any log
ASA(config)# exit 

Step 2: Apply the VPN filter to the applicable group policy as shown in the example below.

ASA(config)# group-policy VPN_POLICY attributes 
ASA(config-group-policy)# vpn-filter value RESTRICT_VPN 
ASA(config-group-policy)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA Firewall'
  tag check_id: 'C-43087r665846_chk'
  tag severity: 'medium'
  tag gid: 'V-239854'
  tag rid: 'SV-239854r665848_rule'
  tag stig_id: 'CASA-FW-000030'
  tag gtitle: 'SRG-NET-000061-FW-000001'
  tag fix_id: 'F-43046r665847_fix'
  tag 'documentable'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
