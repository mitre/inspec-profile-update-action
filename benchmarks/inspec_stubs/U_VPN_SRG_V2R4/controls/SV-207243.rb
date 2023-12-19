control 'SV-207243' do
  title 'The VPN Gateway must disable split-tunneling for remote clients VPNs.'
  desc 'Split tunneling would in effect allow unauthorized external connections, making the system more vulnerable to attack and to exfiltration of organizational information.

A VPN hardware or software client with split tunneling enabled provides an unsecured backdoor to the enclave from the Internet. With split tunneling enabled, a remote client has access to the Internet while at the same time has established a secured path to the enclave via an IPsec tunnel. A remote client connected to the Internet that has been compromised by an attacker in the Internet, provides an attack base to the enclave’s private network via the IPsec tunnel. Hence, it is imperative that the VPN gateway enforces a no split-tunneling policy to all remote clients.'
  desc 'check', 'Verify the VPN Gateway disables split-tunneling for remote clients VPNs.

If the VPN Gateway does not disable split-tunneling for remote clients VPNs, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to disable split-tunneling for remote clients VPNs.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7503r378350_chk'
  tag severity: 'medium'
  tag gid: 'V-207243'
  tag rid: 'SV-207243r608988_rule'
  tag stig_id: 'SRG-NET-000369-VPN-001620'
  tag gtitle: 'SRG-NET-000369'
  tag fix_id: 'F-7503r378351_fix'
  tag 'documentable'
  tag legacy: ['SV-106319', 'V-97181']
  tag cci: ['CCI-002397']
  tag nist: ['SC-7 (7)']
end
