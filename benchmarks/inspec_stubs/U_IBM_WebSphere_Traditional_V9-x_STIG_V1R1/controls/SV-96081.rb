control 'SV-96081' do
  title 'The WebSphere Application Server must accept Personal Identity Verification (PIV) credentials from other federal agencies to access the management interface.'
  desc 'Personal Identity Verification (PIV) credentials are those credentials issued by federal agencies that conform to FIPS Publication 201 and supporting guidance documents. OMB Memorandum 11-11 requires federal agencies to continue implementing the requirements specified in HSPD-12 to enable agency-wide use of PIV credentials. PIV credentials are only used in an unclassified environment.

Access may be denied to authorized users if federal agency PIV credentials are not accepted to access the management interface.'
  desc 'check', 'Check that the admin console is enabled for client certificate logon.

In the Deployment Manager, check the file on: <WAS_INSTALL>/profiles/<profileName>/config/cells/<cellName>/applications/isclite.ear/deployments/isclite/isclite.war/WEB-INF/web.xml.

If the XML element "<auth-method>FORM</auth-method>" is present, this is a finding.'
  desc 'fix', 'From the admin console, select System Administration >> Deployment Manager >> Java and Process Management >> Process definition >> Java Virtual Machine >> Custom Properties.

Select "New".

Insert the following case sensitive value into the "Name" field: "adminconsole.certLogin"

Select "Value".

Enter "true".

Click "Apply".

Click "Save".

Select Security >> SSL Certificate and Key management >> SSL Configurations >> Select CellDefaultSSLSettings >> Quality of Protection (QOP) settings.

In the "Client Authentication" drop box, make sure "Supported" or "Required" is selected. 

Click "Apply".

Click "Save".

Save a backup copy and edit the Web.xml file as follows: <WAS_INSTALL>/profiles/<profileName>/config/cells/<cellName>/applications/isclite.ear/deployments/isclite/isclite.war/WEB-INF/web.xml:
--- Change: 
< security-constraint>
<web-resource-collection>
<web-resource-name>Protected Area</web-resource-name>
<url-pattern>/</url-pattern>
--- So it becomes:
< security-constraint>
<web-resource-collection>
<web-resource-name>Protected Area</web-resource-name>
<url-pattern>/</url-pattern>
<url-pattern>/logon.jsp</url-pattern>
<url-pattern>/logonError.jsp</url-pattern>
--- Add these security constraints if not already present:
<security-constraint>
<web-resource-collection>
<web-resource-name>free pages</web-resource-name>
<url-pattern>/*.jsp</url-pattern>
<url-pattern>/css/*</url-pattern>
<url-pattern>/images/*</url-pattern>
<url-pattern>/j_security_check</url-pattern>
</web-resource-collection>
</security-constraint> 
--- Change:
<auth-method>FORM</auth-method>
to
<auth-method>CLIENT-CERT</auth-method>

Save the "web.xml" file.

Stop and restart the Deployment Manager. 

Log on to the admin console using your certificate.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-81077r2_chk'
  tag severity: 'medium'
  tag gid: 'V-81367'
  tag rid: 'SV-96081r1_rule'
  tag stig_id: 'WBSP-AS-001300'
  tag gtitle: 'SRG-APP-000402-AS-000247'
  tag fix_id: 'F-88153r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002009']
  tag nist: ['IA-8 (1)']
end
