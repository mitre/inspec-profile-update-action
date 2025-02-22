control 'SV-30765' do
  title 'Database backup procedures should be defined, documented and implemented.'
  desc 'Database backups provide the required means to restore databases after compromise or loss. Backups help reduce the vulnerability to unauthorized access or hardware loss.'
  desc 'check', 'Review the database backup procedures and implementation evidence.

Evidence of implementation includes records of backup events and physical review of backup media.

Evidence should match the backup plan as recorded in the System Security Plan.

If backup procedures do not exist or not implemented in accordance with the procedures, this is a Finding.

If backups are not performed weekly or more often, this is a Finding.'
  desc 'fix', 'Develop, document and implement database backup procedures.

Include weekly backup procedures and offline backup data storage.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-31182r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15126'
  tag rid: 'SV-30765r1_rule'
  tag stig_id: 'DG0013-ORACLE11'
  tag gtitle: 'DBMS backup procedures'
  tag fix_id: 'F-27676r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Database Administrator']
end
