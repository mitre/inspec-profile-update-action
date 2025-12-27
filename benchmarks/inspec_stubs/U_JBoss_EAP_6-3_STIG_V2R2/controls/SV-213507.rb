control 'SV-213507' do
  title 'JBoss must be configured to produce log records containing information to establish what type of events occurred.'
  desc 'Information system logging capability is critical for accurate forensic analysis.  Without being able to establish what type of event occurred, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible. 

Log record content that may be necessary to satisfy the requirement of this control includes time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Application servers must log all relevant log data that pertains to the application server.  Examples of relevant data include, but are not limited to, Java Virtual Machine (JVM) activity, HTTPD/Web server activity, and application server-related system process activity.'
  desc 'check', 'Log on to the OS of the JBoss server with OS permissions that allow access to JBoss.
Using the relevant OS commands and syntax, cd to the <JBOSS_HOME>/bin/ folder.
Run the jboss-cli script to start the Command Line Interface (CLI).
Connect to the server and authenticate.
Run the command:

For a Managed Domain configuration:
"ls host=master/server/<SERVERNAME>/core-service=management/access=audit/logger=audit-log:write-attribute(name=enabled,value=true)"

For a Standalone configuration:
"ls /core-service=management/access=audit/logger=audit-log:write-attribute(name=enabled,value=true)"

If "enabled" = false, this is a finding.'
  desc 'fix', 'Launch the jboss-cli management interface.
Connect to the server by typing "connect", authenticate as a user in the Superuser role, and run the following command:

For a Managed Domain configuration:
"host=master/server/<SERVERNAME>/core-service=management/access=audit/logger=audit-log:write-attribute(name=enabled,value=true)"

For a Standalone configuration:
"/core-service=management/access=audit/logger=audit-log:write-attribute(name=enabled,value=true)"'
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14730r296187_chk'
  tag severity: 'medium'
  tag gid: 'V-213507'
  tag rid: 'SV-213507r615939_rule'
  tag stig_id: 'JBOS-AS-000110'
  tag gtitle: 'SRG-APP-000095-AS-000056'
  tag fix_id: 'F-14728r296188_fix'
  tag 'documentable'
  tag legacy: ['SV-76729', 'V-62239']
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
