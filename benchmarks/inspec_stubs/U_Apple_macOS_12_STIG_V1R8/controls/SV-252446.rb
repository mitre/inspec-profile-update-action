control 'SV-252446' do
  title 'The macOS system must utilize an ESS solution and implement all DoD required modules.'
  desc 'The macOS system must employ automated mechanisms to determine the state of system components. The DoD requires the installation and use of an approved HBSS solution to be implemented on the operating system. For additional information, reference all applicable HBSS OPORDs and FRAGOs on SIPRNET.'
  desc 'check', 'Verify that there is an approved ESS solution installed on the system.

If there is not an approved ESS solution installed, this is a finding.

Verify that all installed components of the ESS Solution are at the DoD approved minimal version.

If the installed components are not at the DoD approved minimal versions, this is a finding.'
  desc 'fix', 'Install an approved ESS solution onto the system and ensure that all components are at least updated to their DoD approved minimal versions.'
  impact 0.5
  ref 'DPMS Target Apple macOS 12'
  tag check_id: 'C-55902r816150_chk'
  tag severity: 'medium'
  tag gid: 'V-252446'
  tag rid: 'SV-252446r816152_rule'
  tag stig_id: 'APPL-12-000015'
  tag gtitle: 'SRG-OS-000191-GPOS-00080'
  tag fix_id: 'F-55852r816151_fix'
  tag 'documentable'
  tag cci: ['CCI-001233']
  tag nist: ['SI-2 (2)']
end
