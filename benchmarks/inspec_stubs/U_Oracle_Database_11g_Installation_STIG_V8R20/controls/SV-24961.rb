control 'SV-24961' do
  title 'Oracle Application Express or Oracle HTML DB should not be installed on a production database.'
  desc 'The Oracle Application Express, formerly called HTML DB, is an application development component installed by default with Oracle. Unauthorized application development can introduce a variety of vulnerabilities to the database.'
  desc 'check', "From SQL*Plus:
  select count(*) from dba_users where username like 'FLOWS_%';

If the value returned is not 0 and the database is a production system, this is a Finding."
  desc 'fix', 'Remove Application Express using the instruction found in Oracle MetaLink Note 558340.1 from production DBMS systems.

For new installations, select custom installation and de-select Application Express from the selectable options if available.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-28654r1_chk'
  tag severity: 'medium'
  tag gid: 'V-16055'
  tag rid: 'SV-24961r1_rule'
  tag stig_id: 'DO6753-ORACLE11'
  tag gtitle: 'Oracle Application Express'
  tag fix_id: 'F-25681r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
