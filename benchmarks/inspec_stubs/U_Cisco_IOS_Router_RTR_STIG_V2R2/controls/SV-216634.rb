control 'SV-216634' do
  title 'The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to authenticate all received MSDP packets.'
  desc 'MSDP peering with customer network routers presents additional risks to the core, whether from a rogue or misconfigured MSDP-enabled router. MSDP password authentication is used to validate each segment sent on the TCP connection between MSDP peers, protecting the MSDP session against the threat of spoofed packets being injected into the TCP connection stream.'
  desc 'check', 'Review the router configuration to determine if received MSDP packets are authenticated.

ip msdp peer x.1.28.8 remote-as 8
ip msdp password peer x.1.28.8 xxxxxxxxxxxx

If the router does not require MSDP authentication, this is a finding.'
  desc 'fix', 'Configure the router to authenticate MSDP messages as shown in the following example:

R2(config)#ip msdp password peer x.1.28.8 xxxxxxxxxxxx'
  impact 0.5
  ref 'DPMS Target Cisco IOS Router RTR'
  tag check_id: 'C-17869r287271_chk'
  tag severity: 'medium'
  tag gid: 'V-216634'
  tag rid: 'SV-216634r856202_rule'
  tag stig_id: 'CISC-RT-000910'
  tag gtitle: 'SRG-NET-000343-RTR-000002'
  tag fix_id: 'F-17865r287272_fix'
  tag 'documentable'
  tag legacy: ['SV-105805', 'V-96667']
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
