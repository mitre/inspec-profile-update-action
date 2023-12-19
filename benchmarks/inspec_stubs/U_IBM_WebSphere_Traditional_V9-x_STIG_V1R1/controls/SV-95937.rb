control 'SV-95937' do
  title 'The WebSphere Application Server Java 2 security must be enabled.'
  desc 'Java 2 security provides a policy-based fine grained access control mechanism that increases overall system integrity by checking for permissions before allowing access to certain protected system resources. Java 2 Security is independent on J2EE role-based authorization. Java 2 Security guards access to system resources such as file input and output, sockets, and properties, whereas J2EE security guards access to Web resources such as servlets and JSP files. Administrators should understand the possible consequences of enabling Java 2 Security if applications are not prepared for Java 2 Security. Java 2 Security places some new requirements on application developers and administrators. Admins need to make sure that all the applications are granted the required permissions; otherwise, applications may fail to run. By default, applications are granted the permissions recommended in the J2EE 1.3 Specification. For details of default permissions granted to applications in WebSphere, please refer to the following policy files:

/QIBM/ProdData/Java400/jdk14/lib/security/java.policy
/QIBM/UserData/WebASE51/ASE/instance/properties/server.policy
/QIBM/UserData/WebASE51/ASE/instance/config/cells/cell/nodes/node/app.policy
where instance is the name of your instance, cell is the name of your cell, and node is the name of your node.'
  desc 'check', 'From the admin console, select Security >> Global Security >> Java 2 Security. 

If "Use Java 2 security to restrict application access to local resources" is not selected, this is a finding.'
  desc 'fix', 'From the admin console, select Security >> Global Security >> Java 2 Security.

Select the "Use Java 2 security to restrict application access to local resources" check box.

Ensure the application security policies are defined and access permissions are granted accordingly.

Policies are created and access is granted on an application by application basis. Application access to the underlying host is based upon application access requirements.'
  impact 0.7
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80895r1_chk'
  tag severity: 'high'
  tag gid: 'V-81223'
  tag rid: 'SV-95937r1_rule'
  tag stig_id: 'WBSP-AS-000211'
  tag gtitle: 'SRG-APP-000033-AS-000024'
  tag fix_id: 'F-88003r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
