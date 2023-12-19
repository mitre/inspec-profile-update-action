control 'SV-24856' do
  title 'Only authorized system accounts should have the SYSTEM tablespace specified as the default tablespace.'
  desc 'The Oracle SYSTEM tablespace is used by the database to store all DBMS system objects. Other use of the system tablespace may compromise system availability and the effectiveness of host system access controls to the tablespace files.'
  desc 'check', %q(Run the query:
select property_name, property_value
from database_properties
where property_name in
('DEFAULT_PERMANENT_TABLESPACE','DEFAULT_TEMP_TABLESPACE');

If either value is set to "SYSTEM", this is a finding.

Run the query:
select username from dba_users 
where (default_tablespace = 'SYSTEM' or temporary_tablespace = 'SYSTEM')
and username not in
('LBACSYS','OUTLN','SYS','SYSTEM', 'MGMT_VIEW');

If any non-default account records are returned, this is a finding.)
  desc 'fix', 'Create and dedicate tablespaces to support only one application.

Do not share tablespaces between applications.

Do not grant quotas to application object owners on tablespaces not dedicated to their associated application.

Run the queries:

alter database default tablespace <tablespace_name>;
alter database default temporary tablespace <temporary_tablespace_name>;

alter user <username> default tablespace <tablespace_name> temporary tablespace <temporary_tablespace_name>;

Replace <username> with the named user account.
Replace <tablespace_name> with the new default tablespace name.
Replace <temporary_tablespace_name> with the new default temporary tablespace name (typically TEMP).
Repeat the "alter user" for each affected user account.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29413r5_chk'
  tag severity: 'medium'
  tag gid: 'V-3846'
  tag rid: 'SV-24856r4_rule'
  tag stig_id: 'DO0155-ORACLE11'
  tag gtitle: 'Oracle default tablespace assignment'
  tag fix_id: 'F-26440r3_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
