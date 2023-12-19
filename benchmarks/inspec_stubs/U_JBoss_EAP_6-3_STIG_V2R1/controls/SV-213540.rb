control 'SV-213540' do
  title 'The JBoss server must be configured to log all admin activity.'
  desc 'In order to be able to provide a forensic history of activity, the application server must ensure users who are granted a privileged role or those who utilize a separate distinct account when accessing privileged functions or data have their actions logged.

If privileged activity is not logged, no forensic logs can be used to establish accountability for privileged actions that occur on the system.'
  desc 'check', 'Log on to the OS of the JBoss server with OS permissions that allow access to JBoss.
Using the relevant OS commands and syntax, cd to the <JBOSS_HOME>/bin/ folder.
Run the jboss-cli script.
Connect to the server and authenticate.
Run the command:

/core-service=management/access=audit:read-resource(recursive=true)

Under the "logger" => {audit-log} section of the returned response:
If "enabled" => false, this is a finding'
  desc 'fix', 'Launch the jboss-cli management interface substituting standalone or domain for <CONFIG> based upon the server installation.

<JBOSS_HOME>/<CONFIG>/bin/jboss-cli

connect to the server and run the following command:

/core-service=management/access=audit/logger=audit-log:write-attribute(name=enabled,value=true)'
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14763r296286_chk'
  tag severity: 'medium'
  tag gid: 'V-213540'
  tag rid: 'SV-213540r615939_rule'
  tag stig_id: 'JBOS-AS-000480'
  tag gtitle: 'SRG-APP-000343-AS-000030'
  tag fix_id: 'F-14761r296287_fix'
  tag 'documentable'
  tag legacy: ['SV-76797', 'V-62307']
  tag cci: ['CCI-002234']
  tag nist: ['AC-6 (9)']
end
