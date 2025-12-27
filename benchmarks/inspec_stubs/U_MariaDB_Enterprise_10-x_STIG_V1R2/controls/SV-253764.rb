control 'SV-253764' do
  title 'MariaDB must generate audit records when successful logons or connections occur.'
  desc 'For completeness of forensic analysis, it is necessary to track who/what (a user or other principal) logs on to the DBMS.'
  desc 'check', 'Check what filters are in place by running the following as an administrative user: 

MariaDB> SELECT * FROM mysql.server_audit_filters;

Verify connect_events include connect in audit filters. If not, this is a finding. 

Log in to and out of the MariaDB database server. Verify the connect is logged in the audit logfile or syslog depending on how it is configured. 

If connect is not logged this is a finding.'
  desc 'fix', %q(Edit the necessary filters to include  connect_events connect. Example:

MariaDB> DELETE FROM mysql.server_audit_filters WHERE filtername = 'default';

MariaDB> INSERT INTO mysql.server_audit_filters (filtername, rule)
   VALUES ('default',
      JSON_COMPACT(
         '{
            "connect_event": [
               "CONNECT",
               "DISCONNECT"
            ]
         }'
      ));)
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57216r844266_chk'
  tag severity: 'medium'
  tag gid: 'V-253764'
  tag rid: 'SV-253764r844267_rule'
  tag stig_id: 'MADB-10-011200'
  tag gtitle: 'SRG-APP-000503-DB-000350'
  tag fix_id: 'F-57167r841816_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
