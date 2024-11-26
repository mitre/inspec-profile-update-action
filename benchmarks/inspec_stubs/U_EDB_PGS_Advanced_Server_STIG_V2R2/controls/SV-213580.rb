control 'SV-213580' do
  title 'The audit information produced by the EDB Postgres Advanced Server must be protected from unauthorized modification.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve. 

To ensure the veracity of audit data the information system and/or the application must protect audit information from unauthorized modification. 

This requirement can be achieved through multiple methods that will depend upon system architecture and design. Some commonly employed methods include ensuring log files enjoy the proper file system permissions and limiting log data locations. 

Applications providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights that the user enjoys in order to make access decisions regarding the modification of audit data.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity. 

Modification of database audit data could mask the theft of, or the unauthorized modification of, sensitive data stored in the database.'
  desc 'check', 'Verify User ownership, Group ownership, and permissions on the “edb_audit” directory:
> ls –ald <postgresql data directory>/edb_audit
If the User owner is not “enterprisedb”, this is a finding
If the Group owner is not “enterprisedb”, this is a finding.
If the directory is more permissive than 700, this is a finding.

(The default path for the postgresql data directory is /var/lib/ppas/9.5/data, but this will vary according to local circumstances.)'
  desc 'fix', 'Run these commands: 

1) "chown enterprisedb <postgresql data directory>/edb_audit" 

2) "chgrp enterprisedb <postgresql data directory>/edb_audit" 

3) "chmod 700 <postgresql data directory>/edb_audit"

(The default path for the postgresql data directory is /var/lib/ppas/9.5/data, but this will vary according to local circumstances.)'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14802r290052_chk'
  tag severity: 'medium'
  tag gid: 'V-213580'
  tag rid: 'SV-213580r508024_rule'
  tag stig_id: 'PPS9-00-002700'
  tag gtitle: 'SRG-APP-000119-DB-000060'
  tag fix_id: 'F-14800r290053_fix'
  tag 'documentable'
  tag legacy: ['SV-83519', 'V-68915']
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
