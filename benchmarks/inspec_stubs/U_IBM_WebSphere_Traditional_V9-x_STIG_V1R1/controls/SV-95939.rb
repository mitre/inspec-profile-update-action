control 'SV-95939' do
  title 'The WebSphere Application Server Java 2 security must not be bypassed.'
  desc 'WebSphere provides a passive filter mechanism that will allow administrators to set Java 2 security in the admin console as enabled while still allowing applications to access host resources. This setting bypasses the enforcement of Java2 security. Application access is allowed and activity is logged to the system.out file. This feature is to aid in the identification of application access requirements to the underlying host so security policies can be created. This feature is executed via a custom property that is set for each application server instance operating on the WebSphere server. This setting should only be enabled in a development or testing environment in order to identify what applications access requirements are so security policies can then be created.'
  desc 'check', 'If the system is a development or test system, this requirement is NA.

From the admin console, select Servers >> Server Types >> WebSphere application servers.

For each application server, select Server Infrastructure >> Administration >> Custom properties.

If the "com.ibm.websphere.java2secman.norethrow" resource value exists and is set to "true", this is a finding.'
  desc 'fix', 'From the admin console, select Servers >> Server Types >> WebSphere application servers.

For each application server, select Server Infrastructure >> Administration >> Custom properties.

Delete the "com.ibm.websphere.java2secman.norethrow" resource value from production systems.'
  impact 0.7
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80897r1_chk'
  tag severity: 'high'
  tag gid: 'V-81225'
  tag rid: 'SV-95939r1_rule'
  tag stig_id: 'WBSP-AS-000212'
  tag gtitle: 'SRG-APP-000033-AS-000024'
  tag fix_id: 'F-88005r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
