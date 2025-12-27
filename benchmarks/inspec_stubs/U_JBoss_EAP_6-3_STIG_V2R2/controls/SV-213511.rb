control 'SV-213511' do
  title 'The application server must produce log records that contain sufficient information to establish the outcome of events.'
  desc 'Information system logging capability is critical for accurate forensic analysis. Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, filenames involved, access control or flow control rules invoked.

Success and failure indicators ascertain the outcome of a particular application server event or function. As such, they also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response.  Event outcome may also include event-specific results (e.g., the security state of the information system after the event occurred).'
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
  tag check_id: 'C-14734r296199_chk'
  tag severity: 'medium'
  tag gid: 'V-213511'
  tag rid: 'SV-213511r615939_rule'
  tag stig_id: 'JBOS-AS-000130'
  tag gtitle: 'SRG-APP-000099-AS-000062'
  tag fix_id: 'F-14732r296200_fix'
  tag 'documentable'
  tag legacy: ['SV-76737', 'V-62247']
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
