control 'SV-239866' do
  title 'The Cisco ASA must be configured to filter outbound traffic on all internal interfaces.'
  desc 'If outbound communications traffic is not filtered, hostile activity intended to harm other networks or packets from networks destined to unauthorized networks may not be detected and prevented.

Access control policies and access control lists implemented on devices, such as firewalls, that control the flow of network traffic ensure the flow of traffic is only allowed from authorized sources to authorized destinations. Networks with different levels of trust (e.g., the Internet) must be kept separated.

This requirement addresses the binding of the egress filter to the interface/zone rather than the content of the egress filter.'
  desc 'check', 'Step 1: Verify that an ingress ACL has been applied to the internal interface as shown in the example below.

 interface GigabitEthernet0/3
 nameif INSIDE
 security-level 100
 ip address 10.1.11.1 255.255.255.0
…
…
…
access-group INSIDE_2_OUT in interface INSIDE

Step 2: Verify that the ACL only allows outbound traffic using authorized ports and services as shown in the example below.

access-list INSIDE_2_OUT extended permit tcp any any eq www 
access-list INSIDE_2_OUT extended permit tcp any any eq https 
access-list INSIDE_2_OUT extended permit tcp any any eq domain 
access-list INSIDE_2_OUT extended permit tcp any any eq ftp 
access-list INSIDE_2_OUT extended permit tcp any any eq ftp-data 
access-list INSIDE_2_OUT extended permit tcp any host 10.1.22.3 eq ssh
access-list INSIDE_2_OUT extended deny ip any any log

If the ASA is not configured to filter outbound traffic on all internal interfaces, this is a finding.'
  desc 'fix', 'Step 1: Configure the egress ACL similar to the example below.

ASA(config)# access-list INSIDE_2_OUT extended permit tcp any any eq https
ASA(config)# access-list INSIDE_2_OUT extended permit tcp any any eq http
ASA(config)# access-list INSIDE_2_OUT extended permit tcp any any eq domain
ASA(config)# access-list INSIDE_2_OUT extended permit tcp any any eq ftp   
ASA(config)# access-list INSIDE_2_OUT extended permit tcp any any eq ftp-data
ASA(config)# access-list INSIDE_2_OUT extended permit tcp any host 10.1.22.3 eq ssh
ASA(config)# access-list INSIDE_2_OUT extended deny ip any any log      

Step 2: Apply the ACL inbound on the internal interfaces as shown in the example below.

ASA(config)# access-group INSIDE_2_OUT in interface INSIDE 
ASA(config)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA Firewall'
  tag check_id: 'C-43099r665882_chk'
  tag severity: 'medium'
  tag gid: 'V-239866'
  tag rid: 'SV-239866r855808_rule'
  tag stig_id: 'CASA-FW-000240'
  tag gtitle: 'SRG-NET-000364-FW-000032'
  tag fix_id: 'F-43058r665883_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
