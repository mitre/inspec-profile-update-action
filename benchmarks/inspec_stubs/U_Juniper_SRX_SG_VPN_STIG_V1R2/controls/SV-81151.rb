control 'SV-81151' do
  title 'The Juniper SRX Services Gateway VPN must use IKEv2 for IPsec VPN security associations.'
  desc 'Use of IKEv2 leverages DoS protections because of improved bandwidth management and leverages more secure encryption algorithms.'
  desc 'check', 'Verify only IKEv2 is used for the IKE security configuration on all configured gateways. Use of IKEv1 mitigates the risk to a CAT III finding.

Show security ike gateway <VPN-GATEWAY>

If IKEv2 is not used for IKE associations, this is a finding.'
  desc 'fix', 'For site-to-site VPNs, configure the Juniper SRX to use IKEv2 only.

[edit]
set security ike gateway <VPN-GATEWAY> address <GW-IP-ADDRESS>
set security ike gateway <VPN-GATEWAY> version v2-only'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG VPN'
  tag check_id: 'C-67287r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66661'
  tag rid: 'SV-81151r1_rule'
  tag stig_id: 'JUSX-VN-000016'
  tag gtitle: 'SRG-NET-000132'
  tag fix_id: 'F-72737r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
