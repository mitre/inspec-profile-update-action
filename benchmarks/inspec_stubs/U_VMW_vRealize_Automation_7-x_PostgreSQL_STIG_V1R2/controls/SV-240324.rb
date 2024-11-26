control 'SV-240324' do
  title 'The vRA PostgreSQL database must set the log_statement to all.'
  desc 'Changes in categories of information must be tracked. Without an audit trail, unauthorized access to protected data could go undetected.

For detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security Categorization of Federal Information and Information Systems, and FIPS Publication 200, Minimum Security Requirements for Federal Information and Information Systems.'
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*log_statement\b' /storage/db/pgdata/postgresql.conf

If "log_statement" is not "all", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_statement TO 'all';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x PostgreSQL'
  tag check_id: 'C-43557r668814_chk'
  tag severity: 'medium'
  tag gid: 'V-240324'
  tag rid: 'SV-240324r879873_rule'
  tag stig_id: 'VRAU-PG-000415'
  tag gtitle: 'SRG-APP-000502-DB-000348'
  tag fix_id: 'F-43516r668815_fix'
  tag 'documentable'
  tag legacy: ['SV-100075', 'V-89425']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
