control 'SV-225308' do
  title 'Audit records must be backed up onto a different system or media than the system being audited.'
  desc 'Protection of log data includes assuring the log data is not accidentally lost or deleted.  Audit information stored in one location is vulnerable to accidental or incidental deletion or alteration.'
  desc 'check', 'Determine if a process to back up log data to a different system or media than the system being audited has been implemented.  If it has not, this is a finding.'
  desc 'fix', 'Establish and implement a process for backing up log data to another system or media other than the system being audited.'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27007r471266_chk'
  tag severity: 'medium'
  tag gid: 'V-225308'
  tag rid: 'SV-225308r569185_rule'
  tag stig_id: 'WN12-AU-000203-01'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-26995r471267_fix'
  tag 'documentable'
  tag legacy: ['SV-51566', 'V-36672']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
