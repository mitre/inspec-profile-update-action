control 'SV-82371' do
  title 'Access to database files must be limited to relevant processes and to authorized, administrative users.'
  desc 'Applications, including DBMSs, must prevent unauthorized and unintended information transfer via shared system resources. Permitting only DBMS processes and authorized, administrative users to have access to the files where the database resides helps ensure that those files are not shared inappropriately and are not open to backdoor access and manipulation.'
  desc 'check', 'Review the permissions granted to users by the operating system/file system on the database files, database transaction log files, database audit log files, and database backup files. 

If any user/role who is not an authorized system administrator with a need to know or database administrator with a need to know, or a system account for running DBMS processes, is permitted to read/view any of these files, this is a finding.'
  desc 'fix', 'Configure the permissions granted by the operating system/file system on the database files, database transaction log files, database audit log files, and database backup files so that only relevant system accounts and authorized system administrators and database administrators with a need to know are permitted to read/view these files.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2014'
  tag check_id: 'C-68449r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67881'
  tag rid: 'SV-82371r1_rule'
  tag stig_id: 'SQL4-00-031400'
  tag gtitle: 'SRG-APP-000243-DB-000374'
  tag fix_id: 'F-73997r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
