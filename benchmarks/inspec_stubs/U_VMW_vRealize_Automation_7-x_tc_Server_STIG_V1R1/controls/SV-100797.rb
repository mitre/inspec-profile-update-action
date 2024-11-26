control 'SV-100797' do
  title 'tc Server VCAC must be configured with the appropriate ports.'
  desc 'Web servers provide numerous processes, features, and functionalities that utilize TCP/IP ports. Some of these processes may be deemed unnecessary or too unsecure to run on a production system. 

The web server must provide the capability to disable or deactivate network-related services that are deemed to be non-essential to the server mission, are too unsecure, or are prohibited by the PPSM CAL and vulnerability assessments.

An essential configuration file for tc Server is catalina.properties. The ports that tc Server listens to will be configured in that file.'
  desc 'check', "At the command prompt, execute the following command:

cat /etc/vcac/catalina.properties | grep -E '\\.port'

Review the listed ports. Verify that they match the list below of tc Server VCAC ports.

base.shutdown.port=-1
base.jmx.port=6969
ajp.http.port=8009
ajp.https.port=8443

If the displayed ports do not match the above list of ports, this is a finding."
  desc 'fix', 'Navigate to and open /etc/vcac/catalina.properties.

Navigate to the ports specification section.

Set the tc Server VCAC port specifications according to the list below:

base.shutdown.port=-1
base.jmx.port=6969
ajp.http.port=8009
ajp.https.port=8443'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x tcServer'
  tag check_id: 'C-89839r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90147'
  tag rid: 'SV-100797r1_rule'
  tag stig_id: 'VRAU-TC-000815'
  tag gtitle: 'SRG-APP-000383-WSR-000175'
  tag fix_id: 'F-96889r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
