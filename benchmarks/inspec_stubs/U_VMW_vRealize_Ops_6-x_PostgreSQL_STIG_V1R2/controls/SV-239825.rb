control 'SV-239825' do
  title 'The vROps PostgreSQL DB must generate audit records when categories of information (e.g., classification levels/security levels) are deleted.'
  desc 'Changes in categories of information must be tracked. Without an audit trail, unauthorized access to protected data could go undetected.

For detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security Categorization of Federal Information and Information Systems, and FIPS Publication 200, Minimum Security Requirements for Federal Information and Information Systems.'
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*log_statement\b' /storage/db/vcops/vpostgres/data/postgresql.conf

If "log_statement" is not set to "all", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_statement TO 'all';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x PostgreSQL'
  tag check_id: 'C-43058r663850_chk'
  tag severity: 'medium'
  tag gid: 'V-239825'
  tag rid: 'SV-239825r879873_rule'
  tag stig_id: 'VROM-PG-000550'
  tag gtitle: 'SRG-APP-000502-DB-000348'
  tag fix_id: 'F-43017r663851_fix'
  tag 'documentable'
  tag legacy: ['SV-98973', 'V-88323']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
