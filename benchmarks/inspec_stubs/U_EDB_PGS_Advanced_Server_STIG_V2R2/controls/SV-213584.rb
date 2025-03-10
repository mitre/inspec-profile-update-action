control 'SV-213584' do
  title 'The EDB Postgres Advanced Server must protect its audit features from unauthorized removal.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the deletion of audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
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
  tag check_id: 'C-14806r290064_chk'
  tag severity: 'medium'
  tag gid: 'V-213584'
  tag rid: 'SV-213584r508024_rule'
  tag stig_id: 'PPS9-00-003100'
  tag gtitle: 'SRG-APP-000123-DB-000204'
  tag fix_id: 'F-14804r290065_fix'
  tag 'documentable'
  tag legacy: ['SV-83527', 'V-68923']
  tag cci: ['CCI-001495']
  tag nist: ['AU-9']
end
