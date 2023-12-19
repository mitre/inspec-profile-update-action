control 'SV-239805' do
  title 'The vROps PostgreSQL DB must provide a warning to appropriate support staff when allocated audit record storage volume reaches 75% of maximum audit record storage capacity.'
  desc 'Organizations are required to use a central log management system, so, under normal conditions, the audit space allocated to the DBMS on its own server will not be an issue. However, space will still be required on the DBMS server for audit records in transit, and, under abnormal conditions, this could fill up. Since a requirement exists to halt processing upon audit failure, a service outage would result.

If support personnel are not notified immediately upon storage volume utilization reaching 75%, they are unable to plan for storage capacity expansion. 

The appropriate support staff include, at a minimum, the ISSO and the DBA/SA.'
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*syslog_facility\b' /storage/db/vcops/vpostgres/data/postgresql.conf

If "syslog_facility" is not set to "local0", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET syslog_facility TO 'local0';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x PostgreSQL'
  tag check_id: 'C-43038r663790_chk'
  tag severity: 'medium'
  tag gid: 'V-239805'
  tag rid: 'SV-239805r879732_rule'
  tag stig_id: 'VROM-PG-000370'
  tag gtitle: 'SRG-APP-000359-DB-000319'
  tag fix_id: 'F-42997r663791_fix'
  tag 'documentable'
  tag legacy: ['SV-98933', 'V-88283']
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
