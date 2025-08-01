control 'SV-50949' do
  title 'The Enhanced Mitigation Experience Toolkit (EMET) v5.5 or later must be installed on the system.'
  desc 'Attackers are constantly looking for vulnerabilities in systems and applications.  The Enhanced Mitigation Experience Toolkit can enable several mechanisms, such as Data Execution Prevention (DEP), Address Space Layout Randomization (ASLR), and Structured Exception Handler Overwrite Protection (SEHOP) on the system and applications adding additional levels of protection.'
  desc 'fix', 'Install EMET v5.5 or later on the system. EMET is available for download from Microsoft.'
  impact 0.7
  ref 'DPMS Target Windows Vista'
  tag severity: 'high'
  tag gid: 'V-39137'
  tag rid: 'SV-50949r6_rule'
  tag stig_id: 'WINGE-000100'
  tag gtitle: 'WINGE-000100'
  tag fix_id: 'F-72815r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
