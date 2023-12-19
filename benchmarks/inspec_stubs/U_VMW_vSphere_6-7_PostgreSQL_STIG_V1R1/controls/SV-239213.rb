control 'SV-239213' do
  title 'VMware Postgres must be configured to log to stderr.'
  desc 'Organizations are required to use a central log management system so, under normal conditions, the audit space allocated to the DBMS on its own server will not be an issue. However, space will still be required on the DBMS server for audit records in transit, and, under abnormal conditions, this could fill up. Because a requirement exists to halt processing upon audit failure, a service outage would result.

If support personnel are not notified immediately upon storage volume utilization reaching 75%, they are unable to plan for storage capacity expansion. 

The appropriate support staff include, at a minimum, the ISSO and the DBA/SA.

'
  desc 'check', %q(At the command prompt, execute the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SHOW log_destination;"|sed -n 3p|sed -e 's/^[ ]*//'

Expected result:

stderr

If the output does not match the expected result, this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_destination TO 'stderr';"

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 PostgreSQL'
  tag check_id: 'C-42446r679010_chk'
  tag severity: 'medium'
  tag gid: 'V-239213'
  tag rid: 'SV-239213r679012_rule'
  tag stig_id: 'VCPG-67-000021'
  tag gtitle: 'SRG-APP-000359-DB-000319'
  tag fix_id: 'F-42405r679011_fix'
  tag satisfies: ['SRG-APP-000359-DB-000319', 'SRG-APP-000515-DB-000318']
  tag 'documentable'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
