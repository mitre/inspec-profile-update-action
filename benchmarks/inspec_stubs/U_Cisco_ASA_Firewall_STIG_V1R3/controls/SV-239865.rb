control 'SV-239865' do
  title 'The Cisco ASA must be configured to filter inbound traffic on all external interfaces.'
  desc 'Unrestricted traffic to the trusted networks may contain malicious traffic that poses a threat to an enclave or to other connected networks. Additionally, unrestricted traffic may transit a network, which uses bandwidth and other resources.

Firewall filters control the flow of network traffic, ensure the flow of traffic is only allowed from authorized sources to authorized destinations. Networks with different levels of trust (e.g., the Internet) must be kept separated.'
  desc 'check', 'Review the ASA configuration to verify that it is filtering inbound traffic on all external interfaces.

access-list OUTSIDE_2_DMZ extended permit tcp any host 10.1.33.2 eq www 
access-list OUTSIDE_2_DMZ extended permit tcp any host 10.1.33.2 eq https 
access-list OUTSIDE_2_DMZ extended permit tcp any host 10.1.33.3 eq ftp 
access-list OUTSIDE_2_DMZ extended permit tcp any host 10.1.33.3 eq ftp-data 
access-list OUTSIDE_2_DMZ extended deny ip any any log
…
…
…
access-group  OUTSIDE_2_DMZ in interface OUTSIDE

If the ASA is not configured to filter inbound traffic on all external interfaces, this is a finding.'
  desc 'fix', 'Step 1: Configure the ACL to allow specific inbound traffic.

ASA(config)# access-list OUTSIDE_2_DMZ extended permit tcp any host 10.1.33.2 eq www 
ASA(config)# access-list OUTSIDE_2_DMZ extended permit tcp any host 10.1.33.2 eq https 
ASA(config)# access-list OUTSIDE_2_DMZ extended permit tcp any host 10.1.33.3 eq ftp 
ASA(config)# access-list OUTSIDE_2_DMZ extended permit tcp any host 10.1.33.3 eq ftp-data 
ASA(config)# access-list OUTSIDE_2_DMZ extended deny ip any any log

Step 2: Apply the ACL inbound to the external interface.

ASA(config)#  access-group  OUTSIDE_2_DMZ in interface OUTSIDE'
  impact 0.5
  ref 'DPMS Target Cisco ASA Firewall'
  tag check_id: 'C-43098r665879_chk'
  tag severity: 'medium'
  tag gid: 'V-239865'
  tag rid: 'SV-239865r855807_rule'
  tag stig_id: 'CASA-FW-000230'
  tag gtitle: 'SRG-NET-000364-FW-000031'
  tag fix_id: 'F-43057r665880_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
