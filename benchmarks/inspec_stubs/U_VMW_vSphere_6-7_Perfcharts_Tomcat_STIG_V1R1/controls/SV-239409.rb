control 'SV-239409' do
  title 'Performance Charts application files must be verified for their integrity.'
  desc 'Verifying that the Security Token Service application code is unchanged from its shipping state is essential for file validation and nonrepudiation of Performance Charts. There is no reason that the MD5 hash of the rpm original files should be changed after installation, excluding configuration files.'
  desc 'check', 'At the command prompt, execute the following command:

# rpm -V VMware-perfcharts|grep "^..5......"|grep "/usr/lib"|grep -v -E "\\.properties|\\.conf|\\.xml"

If any files are returned, this is a finding.'
  desc 'fix', 'Reinstall the VCSA or roll back to a snapshot. Modifying the Performance Charts installation files manually is not supported by VMware.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Perfcharts Tomcat'
  tag check_id: 'C-42642r674948_chk'
  tag severity: 'medium'
  tag gid: 'V-239409'
  tag rid: 'SV-239409r674950_rule'
  tag stig_id: 'VCPF-67-000008'
  tag gtitle: 'SRG-APP-000131-WSR-000051'
  tag fix_id: 'F-42601r674949_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
