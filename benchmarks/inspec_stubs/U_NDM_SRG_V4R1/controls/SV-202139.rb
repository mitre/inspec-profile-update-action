control 'SV-202139' do
  title 'The network device must obtain its public key certificates from an appropriate certificate policy through an approved service provider.'
  desc 'For user certificates, each organization obtains certificates from an approved, shared service provider, as required by OMB policy. For federal agencies operating a legacy public key infrastructure cross-certified with the Federal Bridge Certification Authority at medium assurance or higher, this Certification Authority will suffice.'
  desc 'check', 'Determine if the network device obtains public key certificates from an appropriate certificate policy through an approved service provider.

If the network device does not obtain its public key certificates from an appropriate certificate policy through an approved service provider, this is a finding.'
  desc 'fix', 'Configure the network device to obtain its public key certificates from an appropriate certificate policy through an approved service provider.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2265r382079_chk'
  tag severity: 'medium'
  tag gid: 'V-202139'
  tag rid: 'SV-202139r401224_rule'
  tag stig_id: 'SRG-APP-000516-NDM-000344'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-2266r382080_fix'
  tag 'documentable'
  tag legacy: ['SV-69559', 'V-55313']
  tag cci: ['CCI-000366', 'CCI-001159']
  tag nist: ['CM-6 b', 'SC-17 a']
end
