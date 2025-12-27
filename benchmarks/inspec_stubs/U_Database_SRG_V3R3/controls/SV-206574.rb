control 'SV-206574' do
  title 'Access to database files must be limited to relevant processes and to authorized, administrative users.'
  desc 'Applications, including DBMSs, must prevent unauthorized and unintended information transfer via shared system resources. Permitting only DBMS processes and authorized, administrative users to have access to the files where the database resides helps ensure that those files are not shared inappropriately and are not open to backdoor access and manipulation.'
  desc 'check', 'Review the permissions granted to users by the operating system/file system on the database files, database log files and database backup files. 

If any user/role who is not an authorized system administrator with a need to know or database administrator with a need to know, or a system account for running DBMS processes, is permitted to read/view any of these files, this is a finding.'
  desc 'fix', 'Configure the permissions granted by the operating system/file system on the database files, database log files, and database backup files so that only relevant system accounts and authorized system administrators and database administrators with a need to know are permitted to read/view these files.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6834r291390_chk'
  tag severity: 'medium'
  tag gid: 'V-206574'
  tag rid: 'SV-206574r617447_rule'
  tag stig_id: 'SRG-APP-000243-DB-000374'
  tag gtitle: 'SRG-APP-000243'
  tag fix_id: 'F-6834r291391_fix'
  tag 'documentable'
  tag legacy: ['SV-72581', 'V-58151']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
