control 'SV-87301' do
  title 'Access to database files must be limited to relevant processes and to authorized, administrative users.'
  desc 'Applications, including DBMSs, must prevent unauthorized and unintended information transfer via shared system resources. Permitting only DBMS processes and authorized, administrative users to have access to the files where the database resides helps ensure that those files are not shared inappropriately and are not open to backdoor access and manipulation.'
  desc 'check', 'Review the permissions granted to users by the operating system/file system on the database files, database log files, and database backup files. 

At the command prompt, execute the following command:

# find /storage/db/vcops/cassandra/data -type f ! \\( -user admin -o -user root \\)

If any files are listed that are not owned by either "admin" or "root", this is a finding.'
  desc 'fix', 'Configure the permissions granted by the operating system/file system on the database files, database log files, and database backup files so that only relevant system accounts and authorized system administrators and database administrators with a need to know are permitted to read/view these files.

At the command line execute the following command:

# chown root <file>

Replace <file> with the files that are not owned by either "admin" or "root".'
  impact 0.5
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72825r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72669'
  tag rid: 'SV-87301r1_rule'
  tag stig_id: 'VROM-CS-000180'
  tag gtitle: 'SRG-APP-000243-DB-000374'
  tag fix_id: 'F-79073r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
