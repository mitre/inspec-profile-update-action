control 'SV-100793' do
  title 'tc Server HORIZON must be configured with the appropriate ports.'
  desc 'Web servers provide numerous processes, features, and functionalities that utilize TCP/IP ports. Some of these processes may be deemed unnecessary or too unsecure to run on a production system. 

The web server must provide the capability to disable or deactivate network-related services that are deemed to be non-essential to the server mission, are too unsecure, or are prohibited by the PPSM CAL and vulnerability assessments.

An essential configuration file for tc Server is catalina.properties. The ports that tc Server listens to will be configured in that file.'
  desc 'check', "At the command prompt, execute the following command:

cat /opt/vmware/horizon/workspace/conf/catalina.properties | grep -E '\\.port'

Review the listed ports. Verify that they match the list below of tc Server HORIZON ports.

base.shutdown.port=-1
base.jmx.port=6969
bio-ssl.https.port=6443

If the displayed ports do not match the above list of ports, this is a finding."
  desc 'fix', 'Navigate to and open /opt/vmware/horizon/workspace/conf/catalina.properties.

Navigate to the ports specification section.

Set the tc Server HORIZON port specifications according to the list below:

base.shutdown.port=-1
base.jmx.port=6969
bio-ssl.https.port=6443'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x tcServer'
  tag check_id: 'C-89835r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90143'
  tag rid: 'SV-100793r1_rule'
  tag stig_id: 'VRAU-TC-000805'
  tag gtitle: 'SRG-APP-000383-WSR-000175'
  tag fix_id: 'F-96885r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
