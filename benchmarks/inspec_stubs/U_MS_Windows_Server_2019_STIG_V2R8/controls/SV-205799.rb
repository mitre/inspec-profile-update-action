control 'SV-205799' do
  title 'Windows Server 2019 audit records must be backed up to a different system or media than the system being audited.'
  desc 'Protection of log data includes assuring the log data is not accidentally lost or deleted. Audit information stored in one location is vulnerable to accidental or incidental deletion or alteration.'
  desc 'check', 'Determine if a process to back up log data to a different system or media than the system being audited has been implemented.

If it has not, this is a finding.'
  desc 'fix', 'Establish and implement a process for backing up log data to another system or media other than the system being audited.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag check_id: 'C-6064r355759_chk'
  tag severity: 'medium'
  tag gid: 'V-205799'
  tag rid: 'SV-205799r877390_rule'
  tag stig_id: 'WN19-AU-000010'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-6064r355760_fix'
  tag 'documentable'
  tag legacy: ['V-93183', 'SV-103271']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
