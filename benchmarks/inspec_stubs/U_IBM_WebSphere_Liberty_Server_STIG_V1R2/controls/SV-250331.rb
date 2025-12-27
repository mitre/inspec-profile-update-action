control 'SV-250331' do
  title 'The WebSphere Liberty Server must protect software libraries from unauthorized access.'
  desc 'Application servers have the ability to specify that the hosted applications use shared libraries. The application server must have a capability to divide roles based upon duties wherein one project user (such as a developer) cannot modify the shared library code of another project user. The application server must also be able to specify that non-privileged users cannot modify any shared library code at all.'
  desc 'check', 'As a privileged user with local file access to the /opt/IBM/WebSphere/Liberty/lib/ folder, verify all of the jar files in the lib folder have the correct file permissions of 664.

If the file permissions for all jar files in the lib folder are not set to 664, this is a finding.'
  desc 'fix', 'As a privileged user with local file access to the /opt/IBM/WebSphere/Liberty/lib/ folder, verify all of the jar files in the lib folder have the correct file permissions of 664.

If the file permissions for all jar files in the lib folder are not set to 664, use the chmod command to change the file permissions.

chmod 664 *.jar'
  impact 0.5
  ref 'DPMS Target IBM WebSphere Liberty Server'
  tag check_id: 'C-53766r795044_chk'
  tag severity: 'medium'
  tag gid: 'V-250331'
  tag rid: 'SV-250331r795046_rule'
  tag stig_id: 'IBMW-LS-000340'
  tag gtitle: 'SRG-APP-000133-AS-000092'
  tag fix_id: 'F-53720r795045_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
