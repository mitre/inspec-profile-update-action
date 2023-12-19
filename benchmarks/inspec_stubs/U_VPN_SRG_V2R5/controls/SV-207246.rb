control 'SV-207246' do
  title "The IPsec VPN Gateway must use Encapsulating Security Payload (ESP) in tunnel mode for establishing secured paths to transport traffic between the organization's sites or between a gateway and remote end-stations."
  desc 'ESP provides confidentiality, data origin authentication, integrity, and anti-replay services within the IPsec suite of protocols. ESP in tunnel mode ensures a secure path for communications for site-to-site VPNs and gateway to endpoints, including header information.

ESP can be deployed in either transport or tunnel mode. Transport mode is used to create a secured session between two hosts. It can also be used when two hosts simply want to authenticate each IP packet with IPsec authentication header (AH). With ESP transport mode, only the payload (transport layer) is encrypted, whereas with tunnel mode, the entire IP packet is encrypted and encapsulated with a new IP header. Tunnel mode is used to encrypt traffic between secure IPsec gateways or between an IPsec gateway and an end-station running IPsec software. Hence, it is the only method to provide a secured path to transport traffic between remote sites or end-stations and the central site.'
  desc 'check', "Verify the IPsec VPN Gateway uses ESP in tunnel mode for establishing secured paths to transport traffic between the organization's sites or between a gateway and remote end-stations.

If the IPsec VPN Gateway does not enable ESP tunnel mode for establishing secured paths to transport traffic between the organization's sites or between a gateway and remote end-stations, this is a finding."
  desc 'fix', "Configure the IPsec VPN Gateway to use ESP in tunnel mode for establishing secured paths to transport traffic between the organization's sites or between a gateway and remote end-stations."
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7506r856720_chk'
  tag severity: 'medium'
  tag gid: 'V-207246'
  tag rid: 'SV-207246r856721_rule'
  tag stig_id: 'SRG-NET-000375-VPN-001690'
  tag gtitle: 'SRG-NET-000375'
  tag fix_id: 'F-7506r621693_fix'
  tag 'documentable'
  tag legacy: ['SV-106325', 'V-97187']
  tag cci: ['CCI-002423']
  tag nist: ['SC-8 (3)']
end
