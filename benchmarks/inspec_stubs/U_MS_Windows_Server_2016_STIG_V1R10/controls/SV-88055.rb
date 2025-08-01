control 'SV-88055' do
  title 'Windows Server 2016 must, at a minimum, off-load audit records of interconnected systems in real time and off-load standalone systems weekly.'
  desc 'Protection of log data includes assuring the log data is not accidentally lost or deleted. Audit information stored in one location is vulnerable to accidental or incidental deletion or alteration.'
  desc 'check', 'Verify the audit records, at a minimum, are off-loaded for interconnected systems in real time and off-loaded for standalone systems weekly. 

If they are not, this is a finding.'
  desc 'fix', 'Configure the system to, at a minimum, off-load audit records of interconnected systems in real time and off-load standalone systems weekly.'
  impact 0.5
  ref 'DPMS Target Windows 2016'
  tag check_id: 'C-73477r1_chk'
  tag severity: 'medium'
  tag gid: 'V-73403'
  tag rid: 'SV-88055r1_rule'
  tag stig_id: 'WN16-AU-000020'
  tag gtitle: 'SRG-OS-000479-GPOS-00224'
  tag fix_id: 'F-79845r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
