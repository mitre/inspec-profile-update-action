control 'SV-240288' do
  title 'The vRA PostgreSQL database must have the correct permissions on the log files.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve. In addition, access to audit records provides information an attacker could potentially use to his or her advantage.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from any and all unauthorized access. This includes read, write, copy, etc.

This requirement can be achieved through multiple methods which will depend upon system architecture and design. Some commonly employed methods include ensuring log files enjoy the proper file system permissions utilizing file system protections and limiting log data location. 

Additionally, applications with user interfaces to audit records should not allow for the unfettered manipulation of or access to those records via the application. If the application provides access to the audit data, the application becomes accountable for ensuring that audit information is protected from unauthorized access.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.'
  desc 'check', 'At the command prompt, enter the following command:

# ls -l /storage/db/pgdata/pg_log/*.log

If the permissions on any log files are not "600", this is a finding.'
  desc 'fix', %q(At the command prompt, enter the following command:

# chmod 600 /storage/db/pgdata/pg_log/<file_name>

Replace <file_name> with files to be modified.

At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_file_mode TO '0600';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x PostgreSQL'
  tag check_id: 'C-43521r668706_chk'
  tag severity: 'medium'
  tag gid: 'V-240288'
  tag rid: 'SV-240288r879576_rule'
  tag stig_id: 'VRAU-PG-000095'
  tag gtitle: 'SRG-APP-000118-DB-000059'
  tag fix_id: 'F-43480r668707_fix'
  tag 'documentable'
  tag legacy: ['SV-100003', 'V-89353']
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
