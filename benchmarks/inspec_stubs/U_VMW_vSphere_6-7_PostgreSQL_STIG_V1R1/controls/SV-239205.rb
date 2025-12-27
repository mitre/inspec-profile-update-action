control 'SV-239205' do
  title 'VMware Postgres must be configured to use TLS.'
  desc 'The DoD standard for authentication is DoD-approved PKI certificates.

Authentication based on user ID and password may be used only when it is not possible to employ a PKI certificate and requires AO approval.

In such cases, passwords need to be protected at all times, and encryption is the standard method for protecting passwords during transmission.

DBMS passwords sent in clear-text format across the network are vulnerable to discovery by unauthorized users. Disclosure of passwords may easily lead to unauthorized access to the database.

'
  desc 'check', %q(At the command prompt, execute the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SHOW ssl;"|sed -n 3p|sed -e 's/^[ ]*//'

Expected result:

on

If the output does not match the expected result, this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET ssl TO 'on';"

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.7
  ref 'DPMS Target VMware vSphere 6.7 PostgreSQL'
  tag check_id: 'C-42438r678986_chk'
  tag severity: 'high'
  tag gid: 'V-239205'
  tag rid: 'SV-239205r678988_rule'
  tag stig_id: 'VCPG-67-000013'
  tag gtitle: 'SRG-APP-000172-DB-000075'
  tag fix_id: 'F-42397r678987_fix'
  tag satisfies: ['SRG-APP-000172-DB-000075', 'SRG-APP-000442-DB-000379']
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
