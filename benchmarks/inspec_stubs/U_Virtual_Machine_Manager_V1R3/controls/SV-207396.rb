control 'SV-207396' do
  title 'The VMM must use mechanisms meeting the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

VMMs utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements.'
  desc 'check', 'Verify the VMM uses mechanisms meeting the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to use mechanisms meeting the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7653r365598_chk'
  tag severity: 'medium'
  tag gid: 'V-207396'
  tag rid: 'SV-207396r378886_rule'
  tag stig_id: 'SRG-OS-000120-VMM-000600'
  tag gtitle: 'SRG-OS-000120'
  tag fix_id: 'F-7653r365599_fix'
  tag 'documentable'
  tag legacy: ['SV-71253', 'V-56993']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
