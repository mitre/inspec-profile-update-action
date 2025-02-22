control 'SV-253672' do
  title 'MariaDB must be able to generate audit records when privileges/permissions are retrieved.'
  desc 'Under some circumstances, it may be useful to monitor who/what is reading privilege/permission/role information. Therefore, it must be possible to configure auditing to do this. MariaDB makes such information available through an audit log file.

This requirement addresses explicit requests for privilege/permission/role membership information. It does not refer to the implicit retrieval of privileges/permissions/role memberships that MariaDB continually performs to determine if any and every action on the database is permitted.'
  desc 'check', "Verify the MariaDB Enterprise Audit plugin is loaded and actively logging:

MariaDB> SHOW GLOBAL STATUS LIKE 'Server_audit_active';

If the MariaDB Enterprise Audit is not active, this is a finding. 

Check what filters are in place by running the following as an administrative user: 

MariaDB> SELECT * FROM mysql.server_audit_filters;

Verify query_events ALL is included in corresponding audit filters. If not, this is a finding.

MariaDB> SHOW GLOBAL VARIABLES LIKE 'server_audit_file_path';

As a Linux user with sufficient privileges to view logs, tail the audit log file.

$ tail -f /var/log/mysql/server_audit.log (default location)

In another terminal run: 

MariaDB> SHOW GRANTS;

If an audit record is not produced in the first terminal, this is a finding."
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
  tag check_id: 'C-57124r841539_chk'
  tag severity: 'medium'
  tag gid: 'V-253672'
  tag rid: 'SV-253672r841541_rule'
  tag stig_id: 'MADB-10-000700'
  tag gtitle: 'SRG-APP-000091-DB-000066'
  tag fix_id: 'F-57075r841540_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
