control 'SV-225129' do
  title 'The macOS system must utilize an Endpoint Security Solution (ESS) and implement all DoD required modules.'
  desc 'The macOS system must employ automated mechanisms to determine the state of system components. The DoD requires the installation and use of an approved ESS to be implemented on the operating system. For additional information, reference all applicable ESS OPORDs and FRAGOs on SIPRNet.'
  desc 'check', 'Verify that there is an approved ESS installed on the system.

If there is not an approved ESS installed, this is a finding.

Verify that all installed components of the ESS are at the DoD-approved minimal version.

If the installed components are not at the DoD-approved minimal versions, this is a finding.'
  desc 'fix', 'Install an approved ESS onto the system and ensure that all components are at least updated to their DoD-approved minimal versions.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.15'
  tag check_id: 'C-26828r802341_chk'
  tag severity: 'medium'
  tag gid: 'V-225129'
  tag rid: 'SV-225129r802343_rule'
  tag stig_id: 'AOSX-15-000015'
  tag gtitle: 'SRG-OS-000191-GPOS-00080'
  tag fix_id: 'F-26816r802342_fix'
  tag 'documentable'
  tag legacy: ['V-102673', 'SV-111635']
  tag cci: ['CCI-001233']
  tag nist: ['SI-2 (2)']
end
