control 'SV-50951' do
  title 'The Enhanced Mitigation Experience Toolkit (EMET) v5.5 or later must be installed on the system.'
  desc 'Attackers are constantly looking for vulnerabilities in systems and applications.  The Enhanced Mitigation Experience Toolkit can enable several mechanisms, such as Data Execution Prevention (DEP), Address Space Layout Randomization (ASLR), and Structured Exception Handler Overwrite Protection (SEHOP) on the system and applications adding additional levels of protection.'
  desc 'check', 'This is applicable to unclassified systems, for other systems this is NA.

If EMET has not been installed and DEP and SEHOP are configured as required in V-68843 and V-68847, this is NA.

Verify EMET v5.5 or later is installed on the system.

If EMET is not installed, or at the minimum required version, this is a finding.'
  desc 'fix', 'Install EMET v5.5 or later on the system. EMET is available for download from Microsoft.'
  impact 0.7
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-67367r3_chk'
  tag severity: 'high'
  tag gid: 'V-39137'
  tag rid: 'SV-50951r7_rule'
  tag stig_id: 'WINGE-000100'
  tag gtitle: 'WINGE-000100'
  tag fix_id: 'F-72817r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
