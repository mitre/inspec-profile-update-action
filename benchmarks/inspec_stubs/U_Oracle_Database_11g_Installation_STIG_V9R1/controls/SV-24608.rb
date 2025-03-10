control 'SV-24608' do
  title 'Backup and recovery procedures should be developed, documented, implemented and periodically tested.'
  desc 'Problems with backup procedures or backup media may not be discovered until after a recovery is needed. Testing and verification of procedures provides the opportunity to discover oversights, conflicts, or other issues in the backup procedures or use of media designed to be used.'
  desc 'check', 'Review documented backup testing and recovery verification procedures noted or documented in the System Security Plan.

Review evidence of implementation of testing and verification procedures by reviewing logs from backup and recovery implementation.

Logs may be in electronic or hardcopy and may include email or other notification.

If backup testing and recovery verification are not documented or noted in the System Security Plan, this is a Finding.

If evidence of backup testing and recovery verification does not exist, this is a Finding.'
  desc 'fix', 'Design, document and implement backup testing and recovery verification procedures for the DBMS host and all individual database instances and either include or note the name, location, version and current revision date of any external documentation in the System Security Plan.

Include any requirements for documenting database backup and recovery testing and verification activities in the procedures.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29108r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15129'
  tag rid: 'SV-24608r1_rule'
  tag stig_id: 'DG0020-ORACLE11'
  tag gtitle: 'DBMS backup and recovery testing'
  tag fix_id: 'F-26111r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
