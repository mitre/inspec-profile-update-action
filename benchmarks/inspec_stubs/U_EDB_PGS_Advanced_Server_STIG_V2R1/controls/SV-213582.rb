control 'SV-213582' do
  title 'The EDB Postgres Advanced Server must protect its audit features from unauthorized access.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. 

Depending upon the log format and application, system and application log tools may provide the only means to manipulate and manage application and system log data. It is, therefore, imperative that access to audit tools be controlled and protected from unauthorized access. 

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, OS-provided audit tools, vendor-provided audit tools, and open source audit tools needed to successfully view and manipulate audit information system activity and records. 

If an attacker were to gain access to audit tools, he could analyze audit logs for system weaknesses or weaknesses in the auditing itself. An attacker could also manipulate logs to hide evidence of malicious activity.'
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
  tag check_id: 'C-14804r290058_chk'
  tag severity: 'medium'
  tag gid: 'V-213582'
  tag rid: 'SV-213582r508024_rule'
  tag stig_id: 'PPS9-00-002900'
  tag gtitle: 'SRG-APP-000121-DB-000202'
  tag fix_id: 'F-14802r290059_fix'
  tag 'documentable'
  tag legacy: ['V-68919', 'SV-83523']
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
