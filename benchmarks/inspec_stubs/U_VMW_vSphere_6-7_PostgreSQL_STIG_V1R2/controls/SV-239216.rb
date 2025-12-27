control 'SV-239216' do
  title 'VMware Postgres must set client-side character encoding to UTF-8.'
  desc 'A common vulnerability is unplanned behavior when invalid inputs are received. This requirement guards against adverse or unintended system behavior caused by invalid inputs, where information system responses to the invalid input may be disruptive or cause the system to fail to an unsafe state.'
  desc 'check', %q(At the command prompt, execute the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SHOW client_encoding;"|sed -n 3p|sed -e 's/^[ ]*//'

Expected result:

UTF8

If the output does not match the expected result, this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET client_encoding TO 'UTF8';"

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 PostgreSQL'
  tag check_id: 'C-42449r679019_chk'
  tag severity: 'medium'
  tag gid: 'V-239216'
  tag rid: 'SV-239216r879818_rule'
  tag stig_id: 'VCPG-67-000024'
  tag gtitle: 'SRG-APP-000447-DB-000393'
  tag fix_id: 'F-42408r679020_fix'
  tag 'documentable'
  tag cci: ['CCI-002754']
  tag nist: ['SI-10 (3)']
end
