control 'SV-24899' do
  title 'The XDB Protocol server should be uninstalled if not required and authorized for use.'
  desc 'The XML DB supports storage and retrieval of XML data objects in the Oracle Database. It requires the configuration of an Oracle shared-server dispatcher that is activated / used by the Oracle listener to pass http XML requests. If this service is not required, it should be uninstalled.'
  desc 'check', "From SQL*Plus:

  select count(*) from dba_users where username = 'XDB';

  select count(*) from v$parameter where name = 'dispatchers' 
  and value like '%XDB%';

If a value of 0 is returned for either the first or the second SQL statement above, this is not a Finding.

If a value of 1 (or more) is returned for the second SQL statement, review the System Security Plan to verify existence of all XML DB dispatchers is authorized.

If it is not, this is a Finding."
  desc 'fix', 'If the database is authorized to support web services using XML over HTTP, then include documentation and authorization in the System Security Plan.

If not authorized, uninstall XML DB per Oracle MetaLink Note 742014.1.'
  impact 0.3
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29455r1_chk'
  tag severity: 'low'
  tag gid: 'V-3865'
  tag rid: 'SV-24899r1_rule'
  tag stig_id: 'DO0420-ORACLE11'
  tag gtitle: 'Oracle XML DB'
  tag fix_id: 'F-22836r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
