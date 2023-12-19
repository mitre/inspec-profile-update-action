control 'SV-221614' do
  title 'Splunk Enterprise must use TCP for data transmission.'
  desc 'If the UDP protocol is used for communication, then data packets that do not reach the server are not detected as a data loss. The use of TCP to transport data improves delivery reliability, adds data integrity, and gives the option to encrypt the traffic.'
  desc 'check', 'Select Settings >> Data Inputs, and verify there are zero inputs configured under UDP. Splunk supports UDP, but it is not permissible to use. 

If any exist, this is a finding.

If the Web UI is disabled, open an OS command prompt and type:

netstat -a -p UDP

If a UDP connection is displayed for 0.0.0.0:514, the instance is listening for Syslog port 514 in UDP, and this is a finding.'
  desc 'fix', 'Select Settings >> Data Inputs, and verify there are zero inputs configured under UDP. Remove any that exist and recreate using TCP.

It is recommended to set these settings before disabling the web UI of the instance in a distributed environment.'
  impact 0.5
  ref 'DPMS Target Splunk Enterprise 7.x for Windows'
  tag check_id: 'C-23329r416299_chk'
  tag severity: 'medium'
  tag gid: 'V-221614'
  tag rid: 'SV-221614r879887_rule'
  tag stig_id: 'SPLK-CL-000170'
  tag gtitle: 'SRG-APP-000516-AU-000340'
  tag fix_id: 'F-23318r416300_fix'
  tag 'documentable'
  tag legacy: ['SV-111325', 'V-102375']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
