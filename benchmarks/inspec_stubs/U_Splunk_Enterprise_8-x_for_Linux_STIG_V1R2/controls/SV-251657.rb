control 'SV-251657' do
  title 'Splunk Enterprise idle session timeout must be set to not exceed 15 minutes.'
  desc 'Automatic session termination after a period of inactivity addresses the potential for a malicious actor to exploit the unattended session. Closing any unattended sessions reduces the attack surface to the application.

'
  desc 'check', 'This check is performed on the machine used as a search head, which may be a separate machine in a distributed environment.

If the instance being reviewed is not used as a search head, this check in N/A.

Examine the configuration.

Navigate to the $SPLUNK_HOME/etc/system/local/ directory. View the web.conf file.
 
If the web.conf file does not exist, this is a finding.

If the "tools.sessions.timeout" is missing or is configured to 16 or more, this is a finding.'
  desc 'fix', 'This configuration is performed on the machine used as a search head, which may be a separate machine in a distributed environment.

If the web.conf file does not exist, copy the file from $SPLUNK_HOME/etc/system/default to the $SPLUNK_HOME/etc/system/local directory.

Modify/Add the following lines in the web.conf file:

tools.session.timeout = 15'
  impact 0.5
  ref 'DPMS Target Splunk Enterprise 8.x for Linux'
  tag check_id: 'C-55095r819077_chk'
  tag severity: 'medium'
  tag gid: 'V-251657'
  tag rid: 'SV-251657r819079_rule'
  tag stig_id: 'SPLK-CL-000010'
  tag gtitle: 'SRG-APP-000295-AU-000190'
  tag fix_id: 'F-55049r819078_fix'
  tag satisfies: ['SRG-APP-000295-AU-000190', 'SRG-APP-000389-AU-000180']
  tag 'documentable'
  tag cci: ['CCI-002038', 'CCI-002361']
  tag nist: ['IA-11', 'AC-12']
end
