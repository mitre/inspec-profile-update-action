control 'SV-253762' do
  title 'MariaDB must generate audit records when categories of information (e.g., classification levels/security levels) are deleted.'
  desc 'Changes in categories of information must be tracked. Without an audit trail, unauthorized access to protected data could go undetected.

For detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security Categorization of Federal Information and Information Systems, and FIPS Publication 200, Minimum Security Requirements for Federal Information and Information Systems.'
  desc 'check', 'If category tracking is not required in the database, this is not applicable.

Check what filters are in place by running the following as an administrative user: 

MariaDB> SELECT * FROM mysql.server_audit_filters;

Verify query_events ALL is included in corresponding audit filters. If not, this is a finding.'
  desc 'fix', %q(Update necessary audit filters to include query_event ALL. Example: 

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
  tag check_id: 'C-57214r841809_chk'
  tag severity: 'medium'
  tag gid: 'V-253762'
  tag rid: 'SV-253762r841811_rule'
  tag stig_id: 'MADB-10-011000'
  tag gtitle: 'SRG-APP-000502-DB-000348'
  tag fix_id: 'F-57165r841810_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
