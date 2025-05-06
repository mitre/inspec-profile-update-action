control 'SV-225309' do
  title 'The operating system must, at a minimum, off-load audit records of interconnected systems in real time and off-load standalone systems weekly.'
  desc 'Protection of log data includes assuring the log data is not accidentally lost or deleted.  Audit information stored in one location is vulnerable to accidental or incidental deletion or alteration.'
  desc 'check', 'Verify the operating system, at a minimum, off-loads audit records of interconnected systems in real time and off-loads standalone systems weekly.  If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to, at a minimum, off-load audit records of interconnected systems in real time and off-load standalone systems weekly.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27008r471269_chk'
  tag severity: 'medium'
  tag gid: 'V-225309'
  tag rid: 'SV-225309r569185_rule'
  tag stig_id: 'WN12-AU-000203-02'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-26996r471270_fix'
  tag 'documentable'
  tag legacy: ['SV-72133', 'V-57719']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
