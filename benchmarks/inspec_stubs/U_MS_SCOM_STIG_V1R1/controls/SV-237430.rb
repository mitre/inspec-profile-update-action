control 'SV-237430' do
  title 'SCOM SQL Management must be configured to use least privileges.'
  desc "Microsoft SCOM's SQL management requires a Run as solution because the local system account will not have the required permissions to monitor SQL.

If the Run As account is created with elevated database privileges on the SQL endpoint, this can be used to modify SQL databases, breach security boundaries, or otherwise compromise the endpoint."
  desc 'check', 'If the Microsoft SQL management packs for SCOM are not imported, this check is Not Applicable.

Determine which SQL Servers are managed by SCOM:

From the Operations Console, click on the Monitoring workspace. In the left pane, expand the "Microsoft SQL Servers folder" and click on the Computers icon (note older versions of this management pack may be version specific). Make note of the servers listed.

Log on to SQL Server Management Studio and connect to servers being managed in SCOM. Expand the Security Tab and select Logins. 

Verify that NT System\\Authority, NT Service\\HealthService, or the SQL Run As account has not been granted System Admin privileges (SA rights).

If the any of these accounts have been granted SA privileges, this is a finding.'
  desc 'fix', 'Configure the NT System\\Authority or SCOM Run As accounts for least privileges as described in the documentation for the SCOM SQL management pack. The documentation can be found with the management pack download, and permissions may vary depending on the version of the SQL management pack being used. Generally speaking, the account used for monitoring will need to view server state, view any definition, and view any database.

Additional information on this topic can be found at this location along with a management pack that can automate this process: https://kevinholman.com/2016/08/25/sql-mp-run-as-accounts-no-longer-required/'
  impact 0.7
  ref 'DPMS Target Microsoft SCOM'
  tag check_id: 'C-40649r643934_chk'
  tag severity: 'high'
  tag gid: 'V-237430'
  tag rid: 'SV-237430r643936_rule'
  tag stig_id: 'SCOM-AC-000008'
  tag gtitle: 'SRG-APP-000033-NDM-000212'
  tag fix_id: 'F-40612r663056_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
