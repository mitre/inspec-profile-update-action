control 'SV-253772' do
  title 'MariaDB must generate audit records for all direct access to the database(s).'
  desc 'In this context, direct access is any query, command, or call to MariaDB that comes from any source other than the application(s) that it supports. Examples would be the command line or a database management utility program. The intent is to capture all activity from administrative and nonstandard sources.'
  desc 'check', 'Check what filters are in place by running the following as an administrative user: 

MariaDB> SELECT * FROM mysql.server_audit_filters;

Verify connect_events include connect in audit filters. If not, this is a finding.'
  desc 'fix', %q(Edit the necessary filters to include  connect_events connect. Example:

MariaDB> DELETE FROM mysql.server_audit_filters WHERE filtername = 'default';

MariaDB> INSERT INTO mysql.server_audit_filters (filtername, rule)
   VALUES ('default',
      JSON_COMPACT(
         '{
            "connect_event":"CONNECT"
         }'
      ));)
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57224r841839_chk'
  tag severity: 'medium'
  tag gid: 'V-253772'
  tag rid: 'SV-253772r841841_rule'
  tag stig_id: 'MADB-10-012000'
  tag gtitle: 'SRG-APP-000508-DB-000358'
  tag fix_id: 'F-57175r841840_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
