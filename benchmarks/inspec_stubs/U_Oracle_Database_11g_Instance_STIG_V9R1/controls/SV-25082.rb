control 'SV-25082' do
  title 'Credentials stored and used by the DBMS to access remote databases or applications should be authorized and restricted to authorized users.'
  desc 'Credentials defined for access to remote databases or applications may provide unauthorized access to additional databases and applications to unauthorized or malicious users.'
  desc 'check', 'Review the list of defined database links generated from the DBMS.

Compare to the list in the System Security Plan with the DBA.

If no database links are listed in the database and in the System Security Plan, this check is Not a Finding.

If any database links are defined in the DBMS, verify the authorization for the definition in the System Security Plan.

If any database links exist that are not authorized or not listed in the System Security Plan, this is a Finding.'
  desc 'fix', 'Grant access to database links to authorized users or applications only.

Document all database links access authorizations in the System Security Plan.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-942r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15154'
  tag rid: 'SV-25082r1_rule'
  tag stig_id: 'DG0190-ORACLE11'
  tag gtitle: 'DBMS remote system credential use and access'
  tag fix_id: 'F-24662r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
