control 'SV-230754' do
  title 'The macOS system must utilize an HBSS solution and implement all DoD required modules.'
  desc 'The macOS system must employ automated mechanisms to determine the state of system components. The DoD requires the installation and use of an approved HBSS solution to be implemented on the operating system. For additional information, reference all applicable HBSS OPORDs and FRAGOs on SIPRNET.'
  desc 'check', 'Verify that there is an approved HBSS solution installed on the system.

If there is not an approved HBSS solution installed, this is a finding.

Verify that all installed components of the HBSS Solution are at the DoD approved minimal version.

If the installed components are not at the DoD approved minimal versions, this is a finding.'
  desc 'fix', 'Install an approved HBSS solution onto the system and ensure that all components are at least updated to their DoD approved minimal versions.'
  impact 0.5
  ref 'DPMS Target Apple macOS 11'
  tag check_id: 'C-33699r607149_chk'
  tag severity: 'medium'
  tag gid: 'V-230754'
  tag rid: 'SV-230754r599842_rule'
  tag stig_id: 'APPL-11-000015'
  tag gtitle: 'SRG-OS-000191-GPOS-00080'
  tag fix_id: 'F-33672r607150_fix'
  tag 'documentable'
  tag cci: ['CCI-001233']
  tag nist: ['SI-2 (2)']
end
