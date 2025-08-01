control 'SV-239196' do
  title 'VMware Postgres must limit the number of connections.'
  desc 'Database management includes the ability to control the number of users and user sessions utilizing a DBMS. Unlimited concurrent connections to the DBMS could allow a successful denial-of-service (DoS) attack by exhausting connection resources, and a system could fail or be degraded by an overload of legitimate users. Limiting the number of concurrent sessions per user is helpful in reducing these risks.

This requirement addresses concurrent session control for a single account. It does not address concurrent sessions by a single user via multiple system accounts and does not deal with the total number of sessions across all accounts.

The capability to limit the number of concurrent sessions per user must be configured in or added to the DBMS (for example, by use of a logon trigger) when this is technically feasible. Note that it is not sufficient to limit sessions via a web server or application server alone because legitimate users and adversaries can potentially connect to the DBMS by other means.

The organization will need to define the maximum number of concurrent sessions by account type, by account, or a combination thereof. In deciding on the appropriate number, it is important to consider the work requirements of the various types of users. For example, two might be an acceptable limit for general users accessing the database via an application, but 10 might be too few for a database administrator using a database management GUI tool, where each query tab and navigation pane may count as a separate session.

Sessions may also be referred to as connections or logons, which for the purposes of this requirement are synonyms.'
  desc 'check', %q(At the command prompt, execute the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SHOW max_connections;"|sed -n 3p|sed -e 's/^[ ]*//'

Expected result:

345

If the output does not match the expected result, this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET max_connections TO '345';"

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 PostgreSQL'
  tag check_id: 'C-42429r678959_chk'
  tag severity: 'medium'
  tag gid: 'V-239196'
  tag rid: 'SV-239196r678961_rule'
  tag stig_id: 'VCPG-67-000001'
  tag gtitle: 'SRG-APP-000001-DB-000031'
  tag fix_id: 'F-42388r678960_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
