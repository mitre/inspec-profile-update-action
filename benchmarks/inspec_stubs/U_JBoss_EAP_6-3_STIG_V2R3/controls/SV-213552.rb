control 'SV-213552' do
  title 'JBoss must be configured to generate log records when successful/unsuccessful attempts to delete privileges occur.'
  desc 'Deleting privileges of a subject/object may cause a subject/object to gain or lose capabilities.  When successful and unsuccessful privilege deletions are made, the events need to be logged.  By logging the event, the modification or attempted modification can be investigated to determine if it was performed inadvertently or maliciously.'
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
  tag check_id: 'C-14775r296322_chk'
  tag severity: 'medium'
  tag gid: 'V-213552'
  tag rid: 'SV-213552r615939_rule'
  tag stig_id: 'JBOS-AS-000695'
  tag gtitle: 'SRG-APP-000499-AS-000224'
  tag fix_id: 'F-14773r296323_fix'
  tag 'documentable'
  tag legacy: ['SV-76821', 'V-62331']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
