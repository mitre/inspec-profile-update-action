control 'SV-213508' do
  title 'JBoss Log Formatter must be configured to produce log records that establish the date and time the events occurred.'
  desc 'Application server logging capability is critical for accurate forensic analysis.  Without sufficient and accurate information, a correct replay of the events cannot be determined.

Ascertaining the correct order of the events that occurred is important during forensic analysis.  Events that appear harmless by themselves might be flagged as a potential threat when properly viewed in sequence.  By also establishing the event date and time, an event can be properly viewed with an enterprise tool to fully see a possible threat in its entirety.

Without sufficient information establishing when the log event occurred, investigation into the cause of event is severely hindered.  Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, filenames involved, access control, or flow control rules invoked.

In addition to logging event information, application servers must also log the corresponding dates and times of these events. Examples of event data include, but are not limited to, Java Virtual Machine (JVM) activity, HTTPD activity, and application server-related system process activity.'
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
  tag check_id: 'C-14731r296190_chk'
  tag severity: 'medium'
  tag gid: 'V-213508'
  tag rid: 'SV-213508r615939_rule'
  tag stig_id: 'JBOS-AS-000115'
  tag gtitle: 'SRG-APP-000096-AS-000059'
  tag fix_id: 'F-14729r296191_fix'
  tag 'documentable'
  tag legacy: ['SV-76731', 'V-62241']
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end
