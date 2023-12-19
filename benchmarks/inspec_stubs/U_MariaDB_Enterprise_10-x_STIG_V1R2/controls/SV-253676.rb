control 'SV-253676' do
  title 'MariaDB must include additional, more detailed, organization-defined information in the audit records for audit events identified by type, location, or subject.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information. To support analysis, some types of events will need information to be logged that exceeds the basic requirements of event type, time stamps, location, source, outcome, and user identity. If additional information is not available, it could negatively impact forensic investigations into user actions or other malicious events.

The organization must determine what additional information is required for complete analysis of the audited events. The additional information required is dependent on the type of information (e.g., sensitivity of the data and the environment within which it resides). At a minimum, the organization must employ either full-text recording of privileged commands or the individual identities of users of shared accounts, or both. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise. 

Examples of detailed information the organization may require in audit records are full-text recording of privileged commands or the individual identities of shared account users.'
  desc 'check', "Verify the MariaDB Enterprise Audit plugin is loaded and actively logging:

MariaDB> SHOW GLOBAL STATUS LIKE 'Server_audit_active';

If the MariaDB Enterprise Audit is not active, this is a finding. 

Log in to MariaDB Enterprise Server and verify the audit log location. 

MariaDB> SHOW GLOBAL VARIABLES LIKE 'server_audit_file_path';

Verify the necessary audit filters are in place: 

MariaDB> SELECT * FROM mysql.server_audit_filters;

In another terminal, view the audit log file: 

$ tail -f /var/log/mysql/audit.log

Back in the MariaDB shell, run a query which matches an audit filter. Example if query_events is ALL:

MariaDB> SELECT * FROM mysql.help_topic;

Verify the entry was logged in the audit log and contains the necessary event user information. If not, this is a finding."
  desc 'fix', %q(Update necessary audit filters. For example: 

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
  tag check_id: 'C-57128r841551_chk'
  tag severity: 'medium'
  tag gid: 'V-253676'
  tag rid: 'SV-253676r841553_rule'
  tag stig_id: 'MADB-10-001600'
  tag gtitle: 'SRG-APP-000101-DB-000044'
  tag fix_id: 'F-57079r841552_fix'
  tag 'documentable'
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
