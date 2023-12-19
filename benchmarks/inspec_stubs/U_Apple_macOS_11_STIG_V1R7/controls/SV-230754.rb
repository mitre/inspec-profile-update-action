control 'SV-230754' do
  title 'The macOS system must utilize an Endpoint Security Solution (ESS) and implement all DoD required modules.'
  desc 'The macOS system must employ automated mechanisms to determine the state of system components. The DoD requires the installation and use of an approved ESS to be implemented on the operating system. For additional information, reference all applicable ESS OPORDs and FRAGOs on SIPRNET.'
  desc 'check', 'Verify that an approved ESS is installed on the system.

If an approved ESS is not installed, this is a finding.

Verify that all installed components of the ESS are at the DoD-approved minimal version.

If the installed components are not at the DoD-approved minimal versions, this is a finding.'
  desc 'fix', 'Install an approved ESS onto the system and ensure that all components are at least updated to their DoD-approved minimal versions.'
  impact 0.5
  ref 'DPMS Target Apple macOS 11'
  tag check_id: 'C-33699r802344_chk'
  tag severity: 'medium'
  tag gid: 'V-230754'
  tag rid: 'SV-230754r802346_rule'
  tag stig_id: 'APPL-11-000015'
  tag gtitle: 'SRG-OS-000191-GPOS-00080'
  tag fix_id: 'F-33672r802345_fix'
  tag 'documentable'
  tag cci: ['CCI-001233']
  tag nist: ['SI-2 (2)']
end
