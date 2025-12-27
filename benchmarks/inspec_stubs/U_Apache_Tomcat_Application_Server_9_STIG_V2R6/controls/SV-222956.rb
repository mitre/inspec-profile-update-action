control 'SV-222956' do
  title 'Autodeploy must be disabled.'
  desc 'Tomcat allows auto-deployment of applications while Tomcat is running. This can allow untested or malicious applications to be automatically loaded into production. Autodeploy must be disabled in production. 

This requirement is NA for test and development systems on non-production networks. For DevSecOps application environments, the ISSM may authorize autodeploy functions on a production Tomcat system if the mission need specifies it and an application security vulnerability testing and assurance regimen is included in the DevSecOps process.'
  desc 'check', 'If the SSP associated with the Host contains ISSM documented approvals for AutoDeploy, this is not a finding.

From the Tomcat server run the following OS command:

sudo cat $CATALINA_BASE/conf/server.xml | grep -i -C2 autodeploy 

If the command returns no results, this is not a finding.

Review the results for the autoDeploy parameter in each Host element. 

<Host name="YOUR HOST NAME" appbase="webapps" unpackWARs="true" autoDeploy="false"> 

If autoDeploy ="true", this is a finding.'
  desc 'fix', 'From the Tomcat server as a privileged user, edit the $CATALINA_BASE/conf/server.xml file.

Examine each <Host> </Host> element, if the element contains autoDeploy="true", modify the statement to read ", autoDeploy="false".

sudo systemctl restart tomcat
sudo systemctl daemon-reload'
  impact 0.5
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24628r426312_chk'
  tag severity: 'medium'
  tag gid: 'V-222956'
  tag rid: 'SV-222956r879587_rule'
  tag stig_id: 'TCAT-AS-000540'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-24617r426313_fix'
  tag 'documentable'
  tag legacy: ['SV-111437', 'V-102495']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
