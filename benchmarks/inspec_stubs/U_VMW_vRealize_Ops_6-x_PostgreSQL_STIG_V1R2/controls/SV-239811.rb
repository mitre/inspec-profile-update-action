control 'SV-239811' do
  title 'When invalid inputs are received, the vROps PostgreSQL DB must behave in a predictable and documented manner that reflects organizational and system objectives.'
  desc 'A common vulnerability is unplanned behavior when invalid inputs are received. This requirement guards against adverse or unintended system behavior caused by invalid inputs, where information system responses to the invalid input may be disruptive or cause the system to fail into an unsafe state.

The behavior will be derived from the organizational and system requirements and includes, but is not limited to, notification of the appropriate personnel, creating an audit record, and rejecting invalid input.'
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*client_encoding\b' /storage/db/vcops/vpostgres/data/postgresql.conf

If "client_encoding" is not set to "UTF8", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET client_encoding TO 'UTF8';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x PostgreSQL'
  tag check_id: 'C-43044r663808_chk'
  tag severity: 'medium'
  tag gid: 'V-239811'
  tag rid: 'SV-239811r879818_rule'
  tag stig_id: 'VROM-PG-000455'
  tag gtitle: 'SRG-APP-000447-DB-000393'
  tag fix_id: 'F-43003r663809_fix'
  tag 'documentable'
  tag legacy: ['SV-98945', 'V-88295']
  tag cci: ['CCI-002754']
  tag nist: ['SI-10 (3)']
end
