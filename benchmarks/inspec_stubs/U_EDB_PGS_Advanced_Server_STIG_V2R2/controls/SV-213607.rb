control 'SV-213607' do
  title 'Access to database files must be limited to relevant processes and to authorized, administrative users.'
  desc 'Applications, including DBMSs, must prevent unauthorized and unintended information transfer via shared system resources. Permitting only DBMS processes and authorized, administrative users to have access to the files where the database resides helps ensure that those files are not shared inappropriately and are not open to backdoor access and manipulation.'
  desc 'check', 'Verify User ownership, Group ownership, and permissions on the <postgressql data directory> directory:
> ls –ald <postgresql data directory>
If the User owner is not “enterprisedb”, this is a finding
If the Group owner is not “enterprisedb”, this is a finding.
If the directory is more permissive than 700, this is a finding.

(The default path for the postgresql data directory is /var/lib/ppas/9.5/data, but this will vary according to local circumstances.)'
  desc 'fix', 'Run these commands:

1) "chown enterprisedb <postgresql data directory>" 

2) "chgrp enterprisedb <postgresql data directory>" 

3) "chmod 700 <postgresql data directory>"

(The default path for the postgresql data directory is /var/lib/ppas/9.5/data, but this will vary according to local circumstances.)'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14829r290133_chk'
  tag severity: 'medium'
  tag gid: 'V-213607'
  tag rid: 'SV-213607r508024_rule'
  tag stig_id: 'PPS9-00-006100'
  tag gtitle: 'SRG-APP-000243-DB-000374'
  tag fix_id: 'F-14827r290134_fix'
  tag 'documentable'
  tag legacy: ['SV-83571', 'V-68967']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
