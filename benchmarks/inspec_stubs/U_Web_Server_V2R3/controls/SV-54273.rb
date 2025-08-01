control 'SV-54273' do
  title 'Web server accounts not utilized by installed features (i.e., tools, utilities, specific services, etc.) must not be created and must be deleted when the web server feature is uninstalled.'
  desc 'When accounts used for web server features such as documentation, sample code, example applications, tutorials, utilities, and services are created even though the feature is not installed, they become an exploitable threat to a web server. 

These accounts become inactive, are not monitored through regular use, and passwords for the accounts are not created or updated. An attacker, through very little effort, can use these accounts to gain access to the web server and begin investigating ways to elevate the account privileges.

The accounts used for web server features not installed must not be created and must be deleted when these features are uninstalled.'
  desc 'check', 'Review the web server documentation to determine the user accounts created when particular features are installed.

Verify the deployed configuration to determine which features are installed with the web server.

If any accounts exist that are not used by the installed features, this is a finding.'
  desc 'fix', 'Use the web server uninstall facility or manually remove the user accounts not used by the installed web server features.'
  impact 0.5
  ref 'DPMS Target SRG-APP-WSR'
  tag check_id: 'C-48093r2_chk'
  tag severity: 'medium'
  tag gid: 'V-41696'
  tag rid: 'SV-54273r3_rule'
  tag stig_id: 'SRG-APP-000141-WSR-000078'
  tag gtitle: 'SRG-APP-000141-WSR-000078'
  tag fix_id: 'F-47155r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
