control 'SV-207495' do
  title 'The VMM must implement cryptographic mechanisms to prevent unauthorized disclosure of all information at rest on all VMM components.'
  desc 'VMMs handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure of the information at rest.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information.'
  desc 'check', 'Verify the VMM implements cryptographic mechanisms to prevent unauthorized disclosure of all information at rest on all VMM components.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to implement cryptographic mechanisms to prevent unauthorized disclosure of all information at rest on all VMM components.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7752r365889_chk'
  tag severity: 'medium'
  tag gid: 'V-207495'
  tag rid: 'SV-207495r854669_rule'
  tag stig_id: 'SRG-OS-000405-VMM-001660'
  tag gtitle: 'SRG-OS-000405'
  tag fix_id: 'F-7752r365890_fix'
  tag 'documentable'
  tag legacy: ['SV-71551', 'V-57291']
  tag cci: ['CCI-002476']
  tag nist: ['SC-28 (1)']
end
