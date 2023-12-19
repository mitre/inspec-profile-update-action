control 'SV-99715' do
  title 'tc Server API must be configured with the appropriate ports.'
  desc 'Web servers provide numerous processes, features, and functionalities that utilize TCP/IP ports. Some of these processes may be deemed unnecessary or too unsecure to run on a production system. 

The web server must provide the capability to disable or deactivate network-related services that are deemed to be non-essential to the server mission, are too unsecure, or are prohibited by the PPSM CAL and vulnerability assessments.

An essential configuration file for tc Server is “catalina.properties”. The ports that tc Server listens to will be configured in that file.'
  desc 'check', "At the command prompt, execute the following command:

cat /usr/lib/vmware-vcops/tomcat-enterprise/conf/catalina.properties | grep -E '\\.port'

Review the listed ports.

Verify that they match the list  below of tc Server API ports.

base.shutdown.port=-1
bio-ssl.https.port=8440
bio.http.port=8081
bio.https.port=8440
jk.port=8010
vmware-ajp13.jk.port=8010
vmware-ajp13.https.port=8440
vmware-ssl.https.port=8440
vmware-ajp13.jk.port=8010
vmware-ajp13.https.port=8440

If the ports are not as listed, this is a finding."
  desc 'fix', 'Navigate to and open /usr/lib/vmware-vcops/tomcat-enterprise/conf/catalina.properties.

Navigate to the ports specification section.

Set the tc Server API port specifications according to the list below:

base.shutdown.port=-1
bio-ssl.https.port=8440
bio.http.port=8081
bio.https.port=8440
jk.port=8010
vmware-ajp13.jk.port=8010
vmware-ajp13.https.port=8440
vmware-ssl.https.port=8440
vmware-ajp13.jk.port=8010
vmware-ajp13.https.port=8440'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x tcServer'
  tag check_id: 'C-88757r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89065'
  tag rid: 'SV-99715r1_rule'
  tag stig_id: 'VROM-TC-000855'
  tag gtitle: 'SRG-APP-000383-WSR-000175'
  tag fix_id: 'F-95807r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
