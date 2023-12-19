control 'SV-206636' do
  title 'The DBMS must be able to generate audit records when successful accesses to objects occur.'
  desc 'Without tracking all or selected types of access to all or selected objects (tables, views, procedures, functions, etc.), it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

In an SQL environment, types of access include, but are not necessarily limited to:
SELECT
INSERT
UPDATE
DELETE
EXECUTE'
  desc 'check', 'Review DBMS documentation to verify that administrative users can specify database objects for which access must be audited and can specify which kinds of access must be audited.

If the DBMS is not capable of this, this is a finding.

Review system documentation to determine whether the application owner has specified database objects (tables, views, procedures, functions, etc.) for which access must be audited. Review the DBMS/database security and audit settings to verify that the specified access to the specified objects is audited.

If not, this is a finding.'
  desc 'fix', 'Deploy a DBMS capable of producing the required audit records when object access occurs.

Configure audit settings to create audit records when the specified access to the specified objects occurs.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6896r291576_chk'
  tag severity: 'medium'
  tag gid: 'V-206636'
  tag rid: 'SV-206636r617447_rule'
  tag stig_id: 'SRG-APP-000507-DB-000356'
  tag gtitle: 'SRG-APP-000507'
  tag fix_id: 'F-6896r291577_fix'
  tag 'documentable'
  tag legacy: ['SV-72549', 'V-58119']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
