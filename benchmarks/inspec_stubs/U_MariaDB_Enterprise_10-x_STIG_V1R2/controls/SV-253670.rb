control 'SV-253670' do
  title 'MariaDB must provide audit record generation capability for DoD-defined auditable events within all DBMS/database components.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within MariaDB (e.g., process, module). Certain specific application functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which MariaDB will provide an audit record generation capability as the following: 

(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

(ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities, or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and

(iii) All account creation, modification, disabling, and termination actions.

Organizations may define additional events requiring continuous or ad hoc auditing.'
  desc 'check', "Verify the MariaDB Enterprise Audit plugin is loaded and actively logging:

MariaDB> SHOW GLOBAL STATUS LIKE 'Server_audit_active';

If the MariaDB Enterprise Audit is not active, this is a finding. 

Check what filters are in place by running the following as an administrative user: 

MariaDB> SELECT * FROM mysql.server_audit_filters;

Verify audit filters match organization-defined auditing requirements. If not, this is a finding."
  desc 'fix', %q(Configure MariaDB to generate audit records for at least the DoD minimum set of events.

Edit the mariadb-enterprise.cnf configuration file located in /etc/my.cnf.d/.

Under [mariadb], add the following: 

server_audit_logging = ON 

Save the configuration file. This change will not take effect until MariaDB Enterprise Server is restarted. 

Using the MariaDB Enterprise Audit plugin, MariaDB can be configured to audit these requests. 

The MariaDB Enterprise Audit plugin can be configured to audit these changes. 

Update necessary audit filters. Ex: 

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
      ));

More information about MariaDB auditing can be found here: https://mariadb.com/docs/security/mariadb-enterprise-audit/)
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57122r841533_chk'
  tag severity: 'medium'
  tag gid: 'V-253670'
  tag rid: 'SV-253670r841535_rule'
  tag stig_id: 'MADB-10-000500'
  tag gtitle: 'SRG-APP-000089-DB-000064'
  tag fix_id: 'F-57073r841534_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
