control 'SV-239982' do
  title 'The Cisco ASA VPN remote access server must be configured to disable split-tunneling for remote clients.'
  desc 'Split tunneling would in effect allow unauthorized external connections, making the system more vulnerable to attack and to exfiltration of organizational information.

A VPN hardware or software client with split tunneling enabled provides an unsecured backdoor to the enclave from the internet. With split tunneling enabled, a remote client has access to the internet while at the same time has established a secured path to the enclave via an IPsec tunnel. A remote client connected to the internet that has been compromised by an attacker in the internet provides an attack base to the enclave’s private network via the IPsec tunnel. Hence, it is imperative that the VPN gateway enforces a no split-tunneling policy to all remote clients.'
  desc 'check', 'Verify the ASA disables split-tunneling for remote clients VPNs as shown in the example below.

group-policy ANY_CONNECT_GROUP attributes
 …
 …
 … 
 split-tunnel-policy tunnelall

If the ASA does not disable split-tunneling for remote clients VPNs, this is a finding.'
  desc 'fix', 'Configure the ASA to disable split-tunneling for remote clients VPNs as shown in the example below.

ASA2(config)# group-policy ANY_CONNECT_GROUP attributes
ASA2(config-group-policy)# split-tunnel-policy tunnelall
ASA2(config-group-policy)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43215r666350_chk'
  tag severity: 'medium'
  tag gid: 'V-239982'
  tag rid: 'SV-239982r856176_rule'
  tag stig_id: 'CASA-VN-000700'
  tag gtitle: 'SRG-NET-000369-VPN-001620'
  tag fix_id: 'F-43174r666351_fix'
  tag 'documentable'
  tag cci: ['CCI-002397']
  tag nist: ['SC-7 (7)']
end
