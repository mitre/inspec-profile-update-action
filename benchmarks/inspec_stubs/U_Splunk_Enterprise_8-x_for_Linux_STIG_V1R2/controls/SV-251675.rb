control 'SV-251675' do
  title 'Splunk Enterprise must use TCP for data transmission.'
  desc 'If the UDP protocol is used for communication, then data packets that do not reach the server are not detected as a data loss. The use of TCP to transport data improves delivery reliability, adds data integrity, and gives the option to encrypt the traffic.'
  desc 'check', 'This check is performed on the machine used as an indexer, which may be a separate machine in a distributed environment.

Examine the configuration.

Navigate to the $SPLUNK_HOME/etc/system/local/ directory. View the inputs.conf file.

If any input is configured to use a UDP port, this is a finding.'
  desc 'fix', 'This configuration is performed on the machine used as an indexer, which may be a separate machine in a distributed environment.

Navigate to $SPLUNK_HOME/etc/system/local/

Modify the inputs.conf file to replace any input that is using a UDP port with a TCP port.'
  impact 0.5
  ref 'DPMS Target Splunk Enterprise 8.x for Linux'
  tag check_id: 'C-55113r819095_chk'
  tag severity: 'medium'
  tag gid: 'V-251675'
  tag rid: 'SV-251675r819097_rule'
  tag stig_id: 'SPLK-CL-000270'
  tag gtitle: 'SRG-APP-000516-AU-000340'
  tag fix_id: 'F-55067r819096_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
