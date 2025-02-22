control 'SV-234101' do
  title 'File integrity monitoring of critical executables that Tanium uses must be configured.'
  desc 'Tanium inherently watches files and their respective hash values for change but while Tanium can do file integrity checks of critical executables, it is important to conduct File Integrity Monitoring (FIM) via an outside service such as Host Based Security System (HBSS) or similar security suites with FIM capability. These technologies provide independent monitoring of critical Tanium and system binaries.'
  desc 'check', 'If the site is using Tanium Integrity Monitor, Tanium Integrity Monitor should be used to monitor the file integrity of Tanium critical files.

If Tanium Integrity Monitor is not installed, a third-party file integrity-monitoring tool must be used to monitor Tanium critical executables, defined files within the Tanium Server directory path.

If the file integrity of Tanium critical executables is not monitored, this is a finding.'
  desc 'fix', 'Implement a file integrity monitoring system to monitor the Tanium critical executable files.'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37286r610803_chk'
  tag severity: 'medium'
  tag gid: 'V-234101'
  tag rid: 'SV-234101r612749_rule'
  tag stig_id: 'TANS-SV-000030'
  tag gtitle: 'SRG-APP-000377'
  tag fix_id: 'F-37251r610804_fix'
  tag 'documentable'
  tag legacy: ['SV-102275', 'V-92173']
  tag cci: ['CCI-001811']
  tag nist: ['CM-11 (1)']
end
