control 'SV-50947' do
  title 'The Enhanced Mitigation Experience Toolkit (EMET) must be installed on the system.'
  desc 'Attackers are constantly looking for vulnerabilities in systems and applications.  The Enhanced Mitigation Experience Toolkit can enable several mechanisms, such as Data Execution Prevention (DEP), Address Space Layout Randomization (ASLR) and Structured Exception Handler Overwrite Protection (SEHOP) on the system and applications adding additional levels of protection.'
  desc 'check', 'Verify EMET V3.0 or later is installed on the system.

If EMET is not installed, or at the minimum required version, this is a finding.'
  desc 'fix', 'Install EMET V3.0 or later on the system.  EMET is available for download from Microsoft.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-46493r4_chk'
  tag severity: 'medium'
  tag gid: 'V-39137'
  tag rid: 'SV-50947r2_rule'
  tag stig_id: 'WINGE-000100'
  tag gtitle: 'WINGE-000100'
  tag fix_id: 'F-44105r2_fix'
  tag 'documentable'
  tag ia_controls: 'ECVP-1'
end
