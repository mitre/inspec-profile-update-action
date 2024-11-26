control 'SV-209534' do
  title 'The macOS system must utilize an HBSS solution and implement all DoD required modules.'
  desc 'The macOS system must employ automated mechanisms to determine the state of system components. The DoD requires the installation and use of an approved HBSS solution to be implemented on the operating system. For additional information, reference all applicable HBSS OPORDs and FRAGOs on SIPRNet.'
  desc 'check', 'Verify that there is an approved HBSS solution installed on the system.

If there is not an approved HBSS solution installed, this is a finding.

Verify that all installed components of the HBSS Solution are at the DoD approved minimal version.

If the installed components are not at the DoD approved minimal versions, this is a finding.'
  desc 'fix', 'Install an approved HBSS solution onto the system and ensure that all components are at least updated to their DoD approved minimal versions.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9785r282084_chk'
  tag severity: 'medium'
  tag gid: 'V-209534'
  tag rid: 'SV-209534r610285_rule'
  tag stig_id: 'AOSX-14-000015'
  tag gtitle: 'SRG-OS-000191-GPOS-00080'
  tag fix_id: 'F-9785r282085_fix'
  tag 'documentable'
  tag legacy: ['V-95811', 'SV-104949']
  tag cci: ['CCI-001233']
  tag nist: ['SI-2 (2)']
end
