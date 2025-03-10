control 'SV-224793' do
  title 'Tomcat SSL must be restricted except for ISEC7 EMM Suite tasks.'
  desc 'Restricting the use of SSL helps ensure only authorized users and processes have access to Tomcat Web apps and reduces the attack surface of the ISEC7 EMM Suite. Without protection of the transmitted information, confidentiality and integrity may be compromised since unprotected communications can be intercepted and either read or altered. 

This requirement applies only to those applications that are either distributed or can allow access to data non-locally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, applications need to leverage transmission protection mechanisms, such as TLS, TLS VPNs, or IPSEC.

Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.'
  desc 'check', 'Verify Tomcat SSL is restricted to only ISEC7 EMM Suite tasks.

Log in to the ISEC7 EMM Suite server.
Navigate to <Drive>:\\ProgramFiles\\ISEC7 EMM Suite\\Tomcat\\conf\\
Edit the web.xml file with Notepad.exe
Verify the following entries are present:

<security-constraint>
 <web-resource-collection>
  <web-resource-name>Unsecure</web-resource-name>
  <!-- Agent -->
  <url-pattern>/BNator/agent/*</url-pattern>
  <url-pattern>/app/agent/*</url-pattern>
  <url-pattern>/app/admin/agentinstaller.jnlp</url-pattern>
  <!-- Client -->
  <url-pattern>/app/clients/*</url-pattern>
  <url-pattern>/app/data/*</url-pattern>
  <!-- Remote Control -->
  <url-pattern>/rc/*</url-pattern>
  <!-- Traffic Push -->
  <url-pattern>/BNator/uss/trafficinfo/*</url-pattern>
  <url-pattern>/BNator/data/mds/trafficpush</url-pattern>
  <url-pattern>/BNator/favorites/*</url-pattern>
  <url-pattern>/app/resource/*</url-pattern>
 </web-resource-collection>
</security-constraint>

<security-constraint>
 <web-resource-collection>
  <web-resource-name>Secure</web-resource-name>
  <url-pattern>/*</url-pattern>
 </web-resource-collection>

 <user-data-constraint>
  <transport-guarantee>CONFIDENTIAL</transport-guarantee>
 </user-data-constraint>
</security-constraint>

If Tomcat SSL is not restricted to only ISEC7 EMM Suite tasks, this is a finding.'
  desc 'fix', 'To restrict Tomcat SSL to only ISEC7 EMM Suite tasks, run the ISEC7 integrated installer or use the following manual procedure:

To restrict SSL for all users except for agent task, the user needs to add a security constraint tag to <Drive>:\\ProgramFiles\\ISEC7 EMM Suite\\Tomcat\\conf\\web.xml

Login to the ISEC7 EMM Suite server.
Navigate to <Drive>:\\ProgramFiles\\ISEC7 EMM Suite\\Tomcat\\conf\\
Edit the web.xml file with Notepad.exe
Add the following entry:

<security-constraint>
 <web-resource-collection>
  <web-resource-name>Unsecure</web-resource-name>
  <!-- Agent -->
  <url-pattern>/BNator/agent/*</url-pattern>
  <url-pattern>/app/agent/*</url-pattern>
  <url-pattern>/app/admin/agentinstaller.jnlp</url-pattern>
  <!-- Client -->
  <url-pattern>/app/clients/*</url-pattern>
  <url-pattern>/app/data/*</url-pattern>
  <!-- Remote Control -->
  <url-pattern>/rc/*</url-pattern>
  <!-- Traffic Push -->
  <url-pattern>/BNator/uss/trafficinfo/*</url-pattern>
  <url-pattern>/BNator/data/mds/trafficpush</url-pattern>
  <url-pattern>/BNator/favorites/*</url-pattern>
  <url-pattern>/app/resource/*</url-pattern>
 </web-resource-collection>
</security-constraint>

<security-constraint>
 <web-resource-collection>
  <web-resource-name>Secure</web-resource-name>
  <url-pattern>/*</url-pattern>
 </web-resource-collection>

 <user-data-constraint>
  <transport-guarantee>CONFIDENTIAL</transport-guarantee>
 </user-data-constraint>
</security-constraint>'
  impact 0.5
  ref 'DPMS Target ISEC7 Sphere'
  tag check_id: 'C-26484r461635_chk'
  tag severity: 'medium'
  tag gid: 'V-224793'
  tag rid: 'SV-224793r505933_rule'
  tag stig_id: 'ISEC-06-551700'
  tag gtitle: 'SRG-APP-000439'
  tag fix_id: 'F-26472r461636_fix'
  tag 'documentable'
  tag legacy: ['V-97301', 'SV-106405']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
