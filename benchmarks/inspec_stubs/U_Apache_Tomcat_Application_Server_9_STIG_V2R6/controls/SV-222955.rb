control 'SV-222955' do
  title 'The deployXML attribute must be set to false in hosted environments.'
  desc 'The Host element controls deployment. Automatic deployment allows for simpler management, but also makes it easier for an attacker to deploy a malicious application. Automatic deployment is controlled by the autoDeploy and deployOnStartup attributes. If both are false, only Contexts defined in server.xml will be deployed, and any changes will require a Tomcat restart.

In a hosted environment where web applications may not be trusted, set the deployXML attribute to false to ignore any context.xml packaged with the web application that may try to assign increased privileges to the web application. Note that if the security manager is enabled that the deployXML attribute will default to false.

This requirement is NA for test and development systems on non-production networks. For DevSecOps application environments, the ISSM may authorize autodeploy functions on a production Tomcat system if the mission need specifies it and an application security vulnerability testing and assurance regimen is included in the DevSecOps process.'
  desc 'check', 'If the SSP associated with the Host contains ISSM documented approvals for deployXML, this is not a finding.

From the Tomcat server as a privileged user:

sudo grep -i deployXML $CATALINA_BASE/conf/server.xml

If the deployXML setting is configured as true and there is no documented authorization to allow automatic deployment of applications, this is a finding.'
  desc 'fix', 'Document authorization for application auto deployment in the System Security Plan (SSP).

From the Tomcat server as a privileged user, edit the $CATALINA_BASE/conf/server.xml file.

sudo nano $CATALINA_BASE/conf/server.xml

Locate each <host> element in the server xml file.  

If the deployXML="true" ensure each host is authorized for application auto deployment and document the authorization in the system security plan.

If authorization is not provided, set the deployXML="false".'
  impact 0.5
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24627r426309_chk'
  tag severity: 'medium'
  tag gid: 'V-222955'
  tag rid: 'SV-222955r879587_rule'
  tag stig_id: 'TCAT-AS-000530'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-24616r426310_fix'
  tag 'documentable'
  tag legacy: ['SV-111435', 'V-102493']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
