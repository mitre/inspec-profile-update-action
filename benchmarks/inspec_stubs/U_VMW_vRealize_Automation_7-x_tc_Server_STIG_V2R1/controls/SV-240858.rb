control 'SV-240858' do
  title 'tc Server VCO must be configured with the appropriate ports.'
  desc 'Web servers provide numerous processes, features, and functionalities that utilize TCP/IP ports. Some of these processes may be deemed unnecessary or too unsecure to run on a production system. 

The web server must provide the capability to disable or deactivate network-related services that are deemed to be non-essential to the server mission, are too unsecure, or are prohibited by the PPSM CAL and vulnerability assessments.

An essential configuration file for tc Server is catalina.properties. The ports that tc Server listens to will be configured in that file.'
  desc 'check', "At the command prompt, execute the following command:

cat /etc/vco/app-server/catalina.properties | grep -E '\\.port'

Review the listed ports. Verify that they match the list below of tc Server VCO ports.

ch.dunes.http-server.port=8280
ch.dunes.https-server.port=8281

If the displayed ports do not match the above list of ports, this is a finding."
  desc 'fix', 'Navigate to and open /etc/vco/app-server/catalina.properties.

Navigate to the ports specification section.

Set the tc Server VCO port specifications according to the list below:

ch.dunes.http-server.port=8280
ch.dunes.https-server.port=8281'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-44091r674457_chk'
  tag severity: 'medium'
  tag gid: 'V-240858'
  tag rid: 'SV-240858r674458_rule'
  tag stig_id: 'VRAU-TC-000810'
  tag gtitle: 'SRG-APP-000383-WSR-000175'
  tag fix_id: 'F-44050r674317_fix'
  tag 'documentable'
  tag legacy: ['SV-100795', 'V-90145']
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
