control 'SV-256948' do
  title 'All Automation Controller NGINX webserver accounts not utilized by installed features (i.e., tools, utilities, specific services, etc.) must not be created and must be deleted when the web server feature is uninstalled.'
  desc 'If web server accounts are not being used, they must be deleted when the web server is uninstalled. This is because the accounts become stale over time and are not tended to. Best practice also dictates that if accounts are not going to be used, they must not be created for the same reason. Both situations create an opportunity for web server exploitation.

When accounts used for web server features such as documentation, sample code, example applications, tutorials, utilities, and services are created, even though the feature is not installed, they become an exploitable threat to a web server. These accounts become inactive and are not monitored through regular use, and passwords for the accounts are not created or updated. An attacker can use these accounts to gain access to the web server and begin investigating ways to elevate the account privileges.

The accounts used for all Automation Controller NGINX web server features not installed must not be created and must be deleted when these features are uninstalled.'
  desc 'check', 'As a System Administrator for each Automation Controller NGINX web server, examine NGINX users in /etc/passwd.

Verify a single user "nginix" exists using the command:

[ `grep -c nginx /etc/passwd` == 1 ] || echo FAILED

If "FAILED" is displayed, this is a finding.'
  desc 'fix', 'As a System Administrator for each Automation Controller NGINX web server, reinstall Automation Controller if no "nginx" users exist in /etc/passwd.

Review all users enumerated in /etc/passwd, and remove any that are not attributable to RHEL or Automation Controller and/or organizationally disallowed.'
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller Web Server'
  tag check_id: 'C-60623r902356_chk'
  tag severity: 'medium'
  tag gid: 'V-256948'
  tag rid: 'SV-256948r902358_rule'
  tag stig_id: 'APWS-AT-000290'
  tag gtitle: 'SRG-APP-000141-WSR-000078'
  tag fix_id: 'F-60565r902357_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
