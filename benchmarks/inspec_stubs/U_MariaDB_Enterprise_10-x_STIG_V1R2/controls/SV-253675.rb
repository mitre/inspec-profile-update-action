control 'SV-253675' do
  title 'MariaDB must produce audit records containing sufficient information to establish what type of events occurred.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Without establishing what type of event occurred, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit record content that may be necessary to satisfy the requirement of this policy includes, for example, time stamps, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in the application and audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application. 

Database software is capable of a range of actions on data stored within the database. It is important, for accurate forensic analysis, to know exactly what actions were performed. This requires specific information regarding the event type an audit record is referring to. If event type information is not recorded and stored with the audit record, the record itself is of very limited use.'
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

Verify the entry was logged in the audit log and contains the necessary event type information. If not, this is a finding."
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
  tag check_id: 'C-57127r841548_chk'
  tag severity: 'medium'
  tag gid: 'V-253675'
  tag rid: 'SV-253675r841550_rule'
  tag stig_id: 'MADB-10-001000'
  tag gtitle: 'SRG-APP-000095-DB-000039'
  tag fix_id: 'F-57078r841549_fix'
  tag 'documentable'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
