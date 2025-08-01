control 'SV-81147' do
  title 'The Juniper SRX Services Gateway VPN must use Encapsulating Security Payload (ESP) in tunnel mode.'
  desc 'ESP provides confidentiality, data origin authentication, integrity, and anti-replay services within the IPsec suite of protocols. ESP in tunnel mode ensures a secure path for communications for site-to-site VPNs and gateway to endpoints, including header information.

ESP can be deployed in either transport or tunnel mode. Transport mode is used to create a secured session between two hosts. It can also be used when two hosts simply want to authenticate each IP packet with IPsec authentication header (AH). With ESP transport mode, only the payload (transport layer) is encrypted, whereas with tunnel mode, the entire IP packet is encrypted and encapsulated with a new IP header. Tunnel mode is used to encrypt traffic between secure IPsec gateways or between an IPsec gateway and an end-station running IPsec software. Hence, it is the only method to provide a secured path to transport traffic between remote sites or end-stations and the central site.'
  desc 'check', 'Review all IPsec profiles and zones to verify ESP tunnel mode has been specified.

[edit]
show security ipsec proposal
show security zones security-zone untrust

If all IPsec proposals are not configured for the ESP protocol, this is a finding.

If an Internet Key Exchange (IKE) is not bound to an external host-inbound service to direct all inbound VPN traffic to the VPN interface configured for IKE, this is a finding.'
  desc 'fix', 'Configure Phase 2 for ESP and allow IKE as a host-inbound service within the security zone associated with the IKE gateway’s external interface configuration. Any traffic that you wish to encrypt is routed to this tunnel interface.

Example:

[edit
set security ipsec proposal IPSEC-PROPOSAL protocol esp

Assumes the external interface is associated with the “untrust” zone.

[edit]
set security ike gateway <IKE-PEER> external-interface <EXTERNAL-INTERFACE-NAME>
set security zones security-zone untrust host-inbound-traffic system-services ike'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG VPN'
  tag check_id: 'C-67283r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66657'
  tag rid: 'SV-81147r1_rule'
  tag stig_id: 'JUSX-VN-000014'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-72733r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
