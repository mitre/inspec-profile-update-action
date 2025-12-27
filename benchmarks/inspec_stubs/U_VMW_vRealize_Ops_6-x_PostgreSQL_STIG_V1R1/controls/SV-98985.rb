control 'SV-98985' do
  title 'The vROps PostgreSQL DB must generate audit records when concurrent logons/connections by the same user from different workstations occur.'
  desc 'For completeness of forensic analysis, it is necessary to track who logs on to the DBMS.

Concurrent connections by the same user from multiple workstations may be valid use of the system; or such connections may be due to improper circumvention of the requirement to use the CAC for authentication; or they may indicate unauthorized account sharing; or they may be because an account has been compromised.

(If the fact of multiple, concurrent logons by a given user can be reliably reconstructed from the log entries for other events (logons/connections; voluntary and involuntary disconnections), then it is not mandatory to create additional log entries specifically for this.)'
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*log_connections\b' /storage/db/vcops/vpostgres/data/postgresql.conf

If "log_connections" is not set to "on", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_connections TO 'on';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x PostgreSQL'
  tag check_id: 'C-88027r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88335'
  tag rid: 'SV-98985r1_rule'
  tag stig_id: 'VROM-PG-000585'
  tag gtitle: 'SRG-APP-000506-DB-000353'
  tag fix_id: 'F-95077r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
