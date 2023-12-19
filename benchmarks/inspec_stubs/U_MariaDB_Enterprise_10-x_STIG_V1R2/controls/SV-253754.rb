control 'SV-253754' do
  title 'MariaDB must generate audit records when security objects are modified.'
  desc 'Changes in the database objects (tables, views, procedures, functions) that record and control permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized changes to the security subsystem could go undetected. The database could be severely compromised or rendered inoperative.'
  desc 'check', "Verify the MariaDB Enterprise Audit plugin is loaded and actively logging:

MariaDB> SHOW GLOBAL STATUS LIKE 'Server_audit_active';

If the MariaDB Enterprise Audit is not active, this is a finding. 

Check what filters are in place by running the following as an administrative user: 

MariaDB> SELECT * FROM mysql.server_audit_filters;

Verify query_events ALL is included in corresponding audit filters. If not, this is a finding."
  desc 'fix', %q(The MariaDB Enterprise Audit plugin can be configured to audit these changes. 

Update necessary audit filters to include query_event ALL. Example: 

MariaDB> DELETE FROM mysql.server_audit_filters WHERE filtername = 'default';

MariaDB> INSERT INTO mysql.server_audit_filters (filtername, rule)
   VALUES ('default',
      JSON_COMPACT(
         '{
            "connect_event": [
               "CONNECT",
               "DISCONNECT"
            ],
            "query_event": [
                "ALL"
            ]
         }'
      ));)
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57206r841785_chk'
  tag severity: 'medium'
  tag gid: 'V-253754'
  tag rid: 'SV-253754r841787_rule'
  tag stig_id: 'MADB-10-010200'
  tag gtitle: 'SRG-APP-000496-DB-000334'
  tag fix_id: 'F-57157r841786_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
