control 'SV-240305' do
  title 'The vRA PostgreSQL database must be configured to use a syslog facility.'
  desc 'Organizations are required to use a central log management system, so, under normal conditions, the audit space allocated to the DBMS on its own server will not be an issue. However, space will still be required on the DBMS server for audit records in transit, and, under abnormal conditions, this could fill up. Since a requirement exists to halt processing upon audit failure, a service outage would result.

If support personnel are not notified immediately upon storage volume utilization reaching 75%, they are unable to plan for storage capacity expansion. 

The appropriate support staff include, at a minimum, the ISSO and the DBA/SA.'
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*logging_collector\b' /storage/db/pgdata/postgresql.conf

If "logging_collector" is not "on", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET logging_collector TO 'on';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x PostgreSQL'
  tag check_id: 'C-43538r668757_chk'
  tag severity: 'medium'
  tag gid: 'V-240305'
  tag rid: 'SV-240305r879732_rule'
  tag stig_id: 'VRAU-PG-000290'
  tag gtitle: 'SRG-APP-000359-DB-000319'
  tag fix_id: 'F-43497r668758_fix'
  tag 'documentable'
  tag legacy: ['SV-100037', 'V-89387']
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
