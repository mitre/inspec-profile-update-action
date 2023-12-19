control 'SV-224875' do
  title 'Audit records must be backed up to a different system or media than the system being audited.'
  desc 'Protection of log data includes assuring the log data is not accidentally lost or deleted. Audit information stored in one location is vulnerable to accidental or incidental deletion or alteration.'
  desc 'check', 'Determine if a process to back up log data to a different system or media than the system being audited has been implemented.

If it has not, this is a finding.'
  desc 'fix', 'Establish and implement a process for backing up log data to another system or media other than the system being audited.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26566r465527_chk'
  tag severity: 'medium'
  tag gid: 'V-224875'
  tag rid: 'SV-224875r569186_rule'
  tag stig_id: 'WN16-AU-000010'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-26554r465528_fix'
  tag 'documentable'
  tag legacy: ['SV-88053', 'V-73401']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
