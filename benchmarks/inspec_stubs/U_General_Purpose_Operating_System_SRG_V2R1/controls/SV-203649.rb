control 'SV-203649' do
  title 'The operating system must use mechanisms meeting the requirements of applicable federal laws, Executive orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

Operating systems utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules. 

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a general purpose computing system.'
  desc 'check', 'Verify the operating system uses mechanisms meeting the requirements of applicable federal laws, Executive orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to use mechanisms meeting the requirements of applicable federal laws, Executive orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3774r557192_chk'
  tag severity: 'medium'
  tag gid: 'V-203649'
  tag rid: 'SV-203649r557194_rule'
  tag stig_id: 'SRG-OS-000120-GPOS-00061'
  tag gtitle: 'SRG-OS-000120'
  tag fix_id: 'F-3774r557193_fix'
  tag 'documentable'
  tag legacy: ['V-56785', 'SV-71045']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
