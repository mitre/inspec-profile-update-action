control 'SV-257152' do
  title 'The macOS system must use an Endpoint Security Solution (ESS) and implement all DOD required modules.'
  desc 'The macOS system must employ automated mechanisms to determine the state of system components. The DOD requires the installation and use of an approved ESS solution to be implemented on the operating system. For additional information, reference all applicable ESS OPORDs and FRAGOs on SIPRNet.'
  desc 'check', 'Verify the macOS system is configured with an approved ESS solution.

If an approved ESS solution is not installed, this is a finding.

Verify that all installed components of the ESS solution are at the DOD-approved minimal version.

If the installed components are not at the DOD-approved minimal versions, this is a finding.'
  desc 'fix', 'Configure the macOS system with an approved ESS solution and ensure that all components are at least updated to their DOD-approved minimal versions.'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60837r905087_chk'
  tag severity: 'medium'
  tag gid: 'V-257152'
  tag rid: 'SV-257152r905089_rule'
  tag stig_id: 'APPL-13-000015'
  tag gtitle: 'SRG-OS-000191-GPOS-00080'
  tag fix_id: 'F-60778r905088_fix'
  tag 'documentable'
  tag cci: ['CCI-001233']
  tag nist: ['SI-2 (2)']
end
