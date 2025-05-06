control 'SV-253746' do
  title 'MariaDB must be able to generate audit records when security objects are accessed.'
  desc 'Changes to the security configuration must be tracked.

This requirement applies to situations where security data is retrieved or modified via data manipulation operations, as opposed to via specialized security functionality.

In an SQL environment, types of access include, but are not necessarily limited to:

SELECT
CREATE
INSERT
UPDATE
DELETE
EXECUTE
ALTER
DROP'
  desc 'check', "Verify the MariaDB Enterprise Audit plugin is loaded and actively logging:

MariaDB> SHOW GLOBAL STATUS LIKE 'Server_audit_active';

If the MariaDB Enterprise Audit is not active, this is a finding. 

Check what filters are in place by running the following as an administrative user: 

MariaDB> SELECT * FROM mysql.server_audit_filters;

Verify query_events includes ALL in corresponding audit filters. If not, this is a finding."
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
  tag check_id: 'C-57198r841761_chk'
  tag severity: 'medium'
  tag gid: 'V-253746'
  tag rid: 'SV-253746r841763_rule'
  tag stig_id: 'MADB-10-009400'
  tag gtitle: 'SRG-APP-000492-DB-000332'
  tag fix_id: 'F-57149r841762_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
