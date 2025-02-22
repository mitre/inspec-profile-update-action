control 'SV-100863' do
  title 'The vAMI executable files and library must not be world-writeable.'
  desc 'Application servers have the ability to specify that the hosted applications utilize shared libraries. The application server must have a capability to divide roles based upon duties wherein one project user (such as a developer) cannot modify the shared library code of another project user. The application server must also be able to specify that non-privileged users cannot modify any shared library code at all.'
  desc 'check', 'At the command prompt, execute the following command:

find /opt/vmware/share/vami -perm -0002 -type f

If any files are listed, this is a finding.'
  desc 'fix', 'At the command prompt, enter the following command:

chmod a-w </path/to/file>

Note: Replace </path/to/file> with the file(s) with world-write rights.'
  impact 0.5
  ref 'DPMS Target vRealize Automation 7.x VAMI'
  tag check_id: 'C-89905r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90213'
  tag rid: 'SV-100863r1_rule'
  tag stig_id: 'VRAU-VA-000175'
  tag gtitle: 'SRG-APP-000133-AS-000092'
  tag fix_id: 'F-96955r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
