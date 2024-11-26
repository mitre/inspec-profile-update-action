control 'SV-96025' do
  title 'The WebSphere Application Server multifactor authentication for network access to privileged accounts must be used.'
  desc 'Multifactor authentication creates a layered defense and makes it more difficult for an unauthorized person to access the application server. If one factor is compromised or broken, the attacker still has at least one more barrier to breach before successfully breaking into the target. Unlike a simple username/password scenario where the attacker could gain access by knowing both the username and password without the user knowing his account was compromised, multifactor authentication adds the requirement that the attacker must have something from the user, such as a token, or to biometrically be the user.

Multifactor authentication is defined as: using two or more factors to achieve authentication. 

Factors include: 
(i) something a user knows (e.g., password/PIN); 
(ii) something a user has (e.g., cryptographic identification device, token); or 
(iii) something a user is (e.g., biometric). A CAC or PKI Hardware Token meets this definition.

A privileged account is defined as an information system account with authorizations of a privileged user. These accounts would be capable of accessing the web management interface.

When accessing the application server via a network connection, administrative access to the application server must be PKI Hardware Token enabled.

'
  desc 'check', 'Check that the admin console is enabled for client certificate logon.

In the Deployment Manager, check the file on: <WAS_INSTALL>/profiles/<profileName>/config/cells/<cellName>/applications/isclite.ear/deployments/isclite/isclite.war/WEB-INF/web.xml.

If the "XML element <auth-method>FORM</auth-method>" is present, this is a finding.'
  desc 'fix', 'From the admin console, select System Administration >> Deployment Manager >> Java and Process Management >> Process definition >> Java Virtual Machine >> Custom Properties.

Select "New".

Insert the following case sensitive value into the "Name" field: "adminconsole.certLogin".

Select "Value".

Enter "true".

Click "Apply".

Click "Save".

Select Security >> SSL Certificate and Key management >> SSL Configurations >> Select CellDefaultSSLSettings >> Quality of Protection (QOP) settings.

In the "Client Authentication" drop-box, make sure "Supported" or "Required" is selected. 

Click "Apply".

Click "Save".

Save a backup copy and edit the "Web.xml" file as follows: <WAS_INSTALL>/profiles/<profileName>/config/cells/<cellName>/applications/isclite.ear/deployments/isclite/isclite.war/WEB-INF/web.xml:
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
  tag check_id: 'C-81009r2_chk'
  tag severity: 'medium'
  tag gid: 'V-81311'
  tag rid: 'SV-96025r1_rule'
  tag stig_id: 'WBSP-AS-001030'
  tag gtitle: 'SRG-APP-000149-AS-000102'
  tag fix_id: 'F-88093r2_fix'
  tag satisfies: ['SRG-APP-000149-AS-000102', 'SRG-APP-000391-AS-000239', 'SRG-APP-000392-AS-000240', 'SRG-APP-000151-AS-000103', 'SRG-APP-000177-AS-000126', 'SRG-APP-000402-AS-000247', 'SRG-APP-000403-AS-000248', 'SRG-APP-000404-AS-000249', 'SRG-APP-000219-AS-000147']
  tag 'documentable'
  tag cci: ['CCI-000187', 'CCI-000765', 'CCI-000767', 'CCI-001184', 'CCI-001953', 'CCI-001954', 'CCI-002009', 'CCI-002010', 'CCI-002011']
  tag nist: ['IA-5 (2) (a) (2)', 'IA-2 (1)', 'IA-2 (3)', 'SC-23', 'IA-2 (12)', 'IA-2 (12)', 'IA-8 (1)', 'IA-8 (1)', 'IA-8 (2)']
end
