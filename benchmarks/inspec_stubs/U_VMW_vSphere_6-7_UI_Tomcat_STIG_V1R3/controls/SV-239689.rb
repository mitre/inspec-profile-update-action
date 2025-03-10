control 'SV-239689' do
  title 'vSphere UI application files must be verified for their integrity.'
  desc 'Verifying that the vSphere UI application code is unchanged from its shipping state is essential for file validation and non-repudiation of the vSphere UI. There is no reason that the MD5 hash of the rpm original files should be changed after installation, excluding configuration files.'
  desc 'check', 'At the command prompt, execute the following command:

# rpm -V vsphere-ui|grep "^..5......"|grep -E "\\.war|\\.jar|\\.sh|\\.py"

If is any output, this is a finding.'
  desc 'fix', 'Reinstall the VCSA or roll back to a snapshot. 

Modifying the vSphere UI installation files manually is not supported by VMware.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 UI Tomcat'
  tag check_id: 'C-42922r679171_chk'
  tag severity: 'medium'
  tag gid: 'V-239689'
  tag rid: 'SV-239689r879584_rule'
  tag stig_id: 'VCUI-67-000008'
  tag gtitle: 'SRG-APP-000131-WSR-000051'
  tag fix_id: 'F-42881r679172_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
