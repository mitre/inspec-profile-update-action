control 'SV-214695' do
  title 'The Juniper SRX Services Gateway VPN must disable split-tunneling for remote clients VPNs.'
  desc 'Split tunneling would in effect allow unauthorized external connections, making the system more vulnerable to attack and to exfiltration of organizational information.

A VPN hardware or software client with split tunneling enabled provides an unsecured backdoor to the enclave from the Internet. With split tunneling enabled, a remote client has access to the Internet while at the same time has established a secured path to the enclave via an IPsec tunnel. A remote client connected to the Internet that has been compromised by an attacker in the Internet, provides an attack base to the enclave’s private network via the IPsec tunnel. Hence, it is imperative that the VPN gateway enforces a no split-tunneling policy to all remote clients.

Traffic to the protected resource will go through the specified dynamic VPN tunnel and will therefore be protected by the Juniper SRX firewall’s security policies.'
  desc 'check', 'Verify split-tunneling is disabled.

[edit]
show security dynamic-vpn access-profile <dynamic-vpn-access-profile>

If split-tunneling is not disabled, this is a finding.'
  desc 'fix', 'Configure the VPN tunnel to control what is sent out in clear text. The “remote-protected-resources” command defines what is routed through the tunnel. The “remote-exceptions” command defines what traffic is sent out in clear text. The following is an example.

[edit]
set security dynamic-vpn access-profile <dynamic-vpn-access-profile>
set security dynamic-vpn clients all ipsec-vpn <ipsec-vpn-name>
set security dynamic-vpn clients all remote-protected-resources <IP-address/mask>
set security dynamic-vpn clients all remote-exceptions 0.0.0.0/0'
  impact 0.5
  ref 'DPMS Target Juniper SRX Services Gateway VPN'
  tag check_id: 'C-15896r297672_chk'
  tag severity: 'medium'
  tag gid: 'V-214695'
  tag rid: 'SV-214695r383596_rule'
  tag stig_id: 'JUSX-VN-000028'
  tag gtitle: 'SRG-NET-000369'
  tag fix_id: 'F-15894r297673_fix'
  tag 'documentable'
  tag legacy: ['V-66677', 'SV-81167']
  tag cci: ['CCI-002397']
  tag nist: ['SC-7 (7)']
end
