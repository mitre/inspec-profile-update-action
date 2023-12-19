control 'SV-100047' do
  title 'vRA PostgreSQL database must be configured to validate character encoding to UTF-8.'
  desc 'A common vulnerability is unplanned behavior when invalid inputs are received. This requirement guards against adverse or unintended system behavior caused by invalid inputs, where information system responses to the invalid input may be disruptive or cause the system to fail into an unsafe state.

The behavior will be derived from the organizational and system requirements and includes, but is not limited to, notification of the appropriate personnel, creating an audit record, and rejecting invalid input.'
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*client_encoding\b' /storage/db/pgdata/postgresql.conf

If "client_encoding" is not "UTF8", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET client_encoding TO 'UTF8';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x PostgreSQL'
  tag check_id: 'C-89089r2_chk'
  tag severity: 'medium'
  tag gid: 'V-89397'
  tag rid: 'SV-100047r1_rule'
  tag stig_id: 'VRAU-PG-000320'
  tag gtitle: 'SRG-APP-000447-DB-000393'
  tag fix_id: 'F-96139r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002754']
  tag nist: ['SI-10 (3)']
end
