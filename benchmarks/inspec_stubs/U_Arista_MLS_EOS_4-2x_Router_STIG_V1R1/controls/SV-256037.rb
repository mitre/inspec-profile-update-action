control 'SV-256037' do
  title 'The multicast Rendezvous Point (RP) Arista router must be configured to limit the multicast forwarding cache so that its resources are not saturated by managing an overwhelming number of Protocol Independent Multicast (PIM) and Multicast Source Discovery Protocol (MSDP) source-active entries.'
  desc 'MSDP peering between networks enables sharing of multicast source information. Enclaves with an existing multicast topology using PIM-SM can configure their RP routers to peer with MSDP routers. As a first step of defense against a denial-of-service (DoS) attack, all RP routers must limit the multicast forwarding cache to ensure that router resources are not saturated managing an overwhelming number of PIM and MSDP source-active entries.'
  desc 'check', 'Review the Arista router configuration to determine if forwarding cache thresholds are defined.

Step 1: To verify the ACL is configured to match the prefixes, execute the command "sh ip access-list".

ip access-list PIM_NEIGHBOR_SA_FILTER
   10 deny ip any 224.1.1.0/24
   20 deny ip any 224.1.2.0/24
   30 deny ip any 224.1.3.0/24
   40 deny ip any 224.1.4.0/24
   100 permit ip any any

Step 2: To verify the thresholds are defined for multicast forwarding cache for source-active entries, execute the command "sh run sec router msdp".

router msdp 
 peer 10.1.12.2
  sa-filter in PIM_NEIGHBOR_SA_FILTER
  sa-limit 500

If the Arista RP router is not configured to limit the multicast forwarding cache to ensure its resources are not saturated, this is a finding.'
  desc 'fix', 'Configure the Arista MSDP-enabled RP routers to limit the multicast forwarding cache for source-active entries.

Step 1: Configure the ACL.

ip access-list PIM_NEIGHBOR_SA_FILTER
   10 deny ip any 224.1.1.0/24
   20 deny ip any 224.1.2.0/24
   30 deny ip any 224.1.3.0/24
   40 deny ip any 224.1.4.0/24
   100 permit ip any any
   
Step 2: Apply the ACL in MSDP peer and define the multicast forwarding cache for source-active entries.

router msdp 
 peer 10.1.12.2
  sa-filter in PIM_NEIGHBOR_SA_FILTER
  sa-limit 500'
  impact 0.3
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59713r882451_chk'
  tag severity: 'low'
  tag gid: 'V-256037'
  tag rid: 'SV-256037r882453_rule'
  tag stig_id: 'ARST-RT-000580'
  tag gtitle: 'SRG-NET-000362-RTR-000120'
  tag fix_id: 'F-59656r882452_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
