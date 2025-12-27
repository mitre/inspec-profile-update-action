control 'SV-45718' do
  title 'Network interfaces must not be configured to allow user control.'
  desc 'Configuration of network interfaces should be limited to privileged users.  Manipulation of network interfaces may result in a Denial of Service or bypass of network security mechanisms.'
  desc 'check', "Check the system for user-controlled network interfaces.
# grep -i '^USERCONTROL=' /etc/sysconfig/network/ifcfg* | grep -i yes
If any results are returned with USERCONTROL set to yes, this is a finding."
  desc 'fix', 'Edit the configuration for the user-controlled interface and change the USERCONTROL=’yes’ value to ‘no’.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43084r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22408'
  tag rid: 'SV-45718r1_rule'
  tag stig_id: 'GEN003581'
  tag gtitle: 'GEN003581'
  tag fix_id: 'F-39116r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
