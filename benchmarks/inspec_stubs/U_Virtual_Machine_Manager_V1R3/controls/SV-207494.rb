control 'SV-207494' do
  title 'The VMM must implement cryptographic mechanisms to prevent unauthorized modification of all information at rest on all VMM components.'
  desc 'VMMs handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized modification of the information at rest.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information.'
  desc 'check', 'Verify the VMM implements cryptographic mechanisms to prevent unauthorized modification of all information at rest on all VMM components.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to implement cryptographic mechanisms to prevent unauthorized modification of all information at rest on all VMM components.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7751r365886_chk'
  tag severity: 'medium'
  tag gid: 'V-207494'
  tag rid: 'SV-207494r854668_rule'
  tag stig_id: 'SRG-OS-000404-VMM-001650'
  tag gtitle: 'SRG-OS-000404'
  tag fix_id: 'F-7751r365887_fix'
  tag 'documentable'
  tag legacy: ['V-57289', 'SV-71549']
  tag cci: ['CCI-002475']
  tag nist: ['SC-28 (1)']
end
