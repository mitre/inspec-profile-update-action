control 'SV-213543' do
  title 'Production JBoss servers must log when failed application deployments occur.'
  desc 'Without logging the enforcement of access restrictions against changes to the application server configuration, it will be difficult to identify attempted attacks, and a log trail will not be available for forensic investigation for after-the-fact actions.  Configuration changes may occur to any of the modules within the application server through the management interface, but logging of actions to the configuration of a module outside the application server is not logged.

Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. Enforcement action methods may be as simple as denying access to a file based on the application of file permissions (access restriction). Log items may consist of lists of actions blocked by access restrictions or changes identified after the fact.'
  desc 'check', 'Log on to the OS of the JBoss server with OS permissions that allow access to JBoss. 
Using the relevant OS commands and syntax, cd to the <JBOSS_HOME>/bin/ folder. 
Run the jboss-cli script. 
Connect to the server and authenticate. 
Run the command:

ls /core-service=management/access=audit/logger=audit-log

If "enabled" = false, this is a finding.'
  desc 'fix', 'Launch the jboss-cli management interface substituting standalone or domain for <CONFIG> based upon the server installation.

<JBOSS_HOME>/<CONFIG>/bin/jboss-cli

connect to the server and run the following command:

/core-service=management/access=audit/logger=audit-log:write-attribute(name=enabled,value=true)'
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14766r296295_chk'
  tag severity: 'medium'
  tag gid: 'V-213543'
  tag rid: 'SV-213543r615939_rule'
  tag stig_id: 'JBOS-AS-000550'
  tag gtitle: 'SRG-APP-000381-AS-000089'
  tag fix_id: 'F-14764r296296_fix'
  tag 'documentable'
  tag legacy: ['SV-76803', 'V-62313']
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']
end
