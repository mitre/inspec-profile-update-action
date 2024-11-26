control 'SV-214322' do
  title 'Apache web server application directories,  libraries, and configuration files must only be accessible to privileged users.'
  desc 'When accounts used for web server features such as documentation, sample code, example applications, tutorials, utilities, and services are created even though the feature is not installed, they become an exploitable threat to a web server.

These accounts become inactive, are not monitored through regular use, and passwords for the accounts are not created or updated. An attacker, through very little effort, can use these accounts to gain access to the web server and begin investigating ways to elevate the account privileges.

The accounts used for web server features not installed must not be created and must be deleted when these features are uninstalled.

'
  desc 'check', 'Obtain a list of the user accounts for the system, noting the privileges for each account.

Verify with the System Administrator (SA) or the Information System Security Officer (ISSO) that all privileged accounts are mission essential and documented.

Verify with the SA or the ISSO that all non-administrator access to shell scripts and operating system functions are mission essential and documented.

If undocumented privileged accounts are present, this is a finding.

If undocumented access to shell scripts or operating system functions is present, this is a finding.'
  desc 'fix', 'Ensure non-administrators are not allowed access to the directory tree, the shell, or other operating system functions and utilities.'
  impact 0.7
  ref 'DPMS Target Apache Server 2.4 Windows Server'
  tag check_id: 'C-15534r277469_chk'
  tag severity: 'high'
  tag gid: 'V-214322'
  tag rid: 'SV-214322r879587_rule'
  tag stig_id: 'AS24-W1-000280'
  tag gtitle: 'SRG-APP-000141-WSR-000078'
  tag fix_id: 'F-15532r277470_fix'
  tag satisfies: ['SRG-APP-000141-WSR-000078', 'SRG-APP-000211-WSR-000031', 'SRG-APP-000380-WSR-000072']
  tag 'documentable'
  tag legacy: ['SV-102465', 'V-92377']
  tag cci: ['CCI-000381', 'CCI-001082', 'CCI-001813']
  tag nist: ['CM-7 a', 'SC-2', 'CM-5 (1) (a)']
end
