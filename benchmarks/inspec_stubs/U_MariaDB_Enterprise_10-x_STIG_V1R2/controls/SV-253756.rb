control 'SV-253756' do
  title 'MariaDB must generate audit records when categories of information (e.g., classification levels/security levels) are modified.'
  desc 'Changes in categories of information must be tracked. Without an audit trail, unauthorized access to protected data could go undetected.

For detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security Categorization of Federal Information and Information Systems, and FIPS Publication 200, Minimum Security Requirements for Federal Information and Information Systems.'
  desc 'check', "If category tracking is not required in the database, this is not applicable.

Verify the MariaDB Enterprise Audit plugin is loaded and actively logging:

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
  tag check_id: 'C-57208r841791_chk'
  tag severity: 'medium'
  tag gid: 'V-253756'
  tag rid: 'SV-253756r841793_rule'
  tag stig_id: 'MADB-10-010400'
  tag gtitle: 'SRG-APP-000498-DB-000346'
  tag fix_id: 'F-57159r841792_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
