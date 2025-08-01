control 'SV-234122' do
  title 'The Tanium SQL Server RDBMS must be configured with sufficient free space to ensure audit logging is not impacted.'
  desc 'In order to ensure Tanium has sufficient storage capacity in which to write the audit logs, the SQL Server RDMBS must be configured with sufficient free space.

Consult the server sizing documents located at https://docs.tanium.com/platform_install/platform_install/reference_host_system_sizing_guidelines.html to determine how much free space should be allocated.'
  desc 'check', 'Access the Tanium SQL Server interactively.

Log on to their server with an account that has administrative privileges.

Consult server sizing documentation at https://docs.tanium.com/platform_install/platform_install/reference_host_system_sizing_guidelines.html and the Tanium system administrator to determine the recommended disk space sizing for the size of the Tanium deployment.

Launch File Explorer.
Check the total disk space allocated to the hard drive allocated for the Tanium SQL databases.

Compare the allocated size against the recommended disk space sizing for the size of the Tanium deployment.

If the allocated size is less than the recommended disk space, this is a finding.'
  desc 'fix', 'Work with the Tanium System Administrator and/or database administrator to allocate additional disk space for the volume hosting the Tanium SQL databases.'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37307r610866_chk'
  tag severity: 'medium'
  tag gid: 'V-234122'
  tag rid: 'SV-234122r612749_rule'
  tag stig_id: 'TANS-SV-000056'
  tag gtitle: 'SRG-APP-000357'
  tag fix_id: 'F-37272r610867_fix'
  tag 'documentable'
  tag legacy: ['SV-102317', 'V-92215']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
