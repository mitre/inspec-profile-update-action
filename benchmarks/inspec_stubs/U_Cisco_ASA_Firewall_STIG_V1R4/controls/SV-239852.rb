control 'SV-239852' do
  title 'The Cisco ASA must be configured to filter outbound traffic, allowing only authorized ports and services.'
  desc 'Information flow control regulates where information is allowed to travel within a network and between interconnected networks. Blocking or restricting detected harmful or suspicious communications between interconnected networks enforces approved authorizations for controlling the flow of traffic.

The firewall that filters traffic outbound to interconnected networks with different security policies must be configured to permit or block traffic based on organization-defined traffic authorizations.'
  desc 'check', 'Review the ASA configuration to determine if it only permits outbound traffic using authorized ports and services.

Step 1: Verify that an ingress ACL has been applied to all internal interfaces as shown in the example below.

 interface GigabitEthernet0/0
 nameif INSIDE
 security-level 100
 ip address 10.1.11.1 255.255.255.0
…
…
…
access-group INSIDE _IN in interface INSIDE 

Step 2: Verify that the ingress ACL only allows outbound traffic using authorized ports and services as shown in the example below.

access-list INSIDE _IN extended permit tcp any any eq www 
access-list INSIDE _IN extended permit tcp any any eq https 
access-list INSIDE _IN extended permit tcp any any eq …
access-list INSIDE _IN extended deny ip any any log

If the ASA is not configured to only allow outbound traffic using authorized ports and services, this is a finding.'
  desc 'fix', 'Step 1: Configure the ingress ACL similar to the example below.

ASA(config)# access-list INSIDE_INextended permit tcp any any eq https
ASA(config)# access-list INSIDE_INextended permit tcp any any eq http
ASA(config)# access-list INSIDE_INextended permit tcp any any eq …
ASA(config)# access-list INSIDE_INextended deny ip any any log      

Step 2: Apply the ACL inbound on all internal interfaces as shown in the example below.

ASA(config)# access-group INSIDE_IN in interface INSIDE
ASA(config)# end'
  impact 0.7
  ref 'DPMS Target Cisco ASA Firewall'
  tag check_id: 'C-43085r665840_chk'
  tag severity: 'high'
  tag gid: 'V-239852'
  tag rid: 'SV-239852r665842_rule'
  tag stig_id: 'CASA-FW-000010'
  tag gtitle: 'SRG-NET-000019-FW-000003'
  tag fix_id: 'F-43044r665841_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
