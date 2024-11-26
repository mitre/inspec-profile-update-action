control 'SV-213510' do
  title 'JBoss must be configured to record the IP address and port information used by management interface network traffic.'
  desc 'Application server logging capability is critical for accurate forensic analysis.  Without sufficient and accurate information, a correct replay of the events cannot be determined.

Ascertaining the correct source, e.g., source IP, of the events is important during forensic analysis.  Correctly determining the source will add information to the overall reconstruction of the loggable event.  By determining the source of the event correctly, analysis of the enterprise can be undertaken to determine if the event compromised other assets within the enterprise.

Without sufficient information establishing the source of the logged event, investigation into the cause of event is severely hindered.  Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, filenames involved, access control, or flow control rules invoked.'
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
  tag check_id: 'C-14733r296196_chk'
  tag severity: 'medium'
  tag gid: 'V-213510'
  tag rid: 'SV-213510r615939_rule'
  tag stig_id: 'JBOS-AS-000125'
  tag gtitle: 'SRG-APP-000098-AS-000061'
  tag fix_id: 'F-14731r296197_fix'
  tag 'documentable'
  tag legacy: ['SV-76735', 'V-62245']
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
