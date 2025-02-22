control 'SV-62603' do
  title 'The McAfee MOVE AV Agentless SVAadmin account password must be changed from the default.'
  desc 'The pre-configured Security Virtual Appliance (SVA)  comes with a default password for the SVAadmin account. This account has root privileges to the Linux O/S of the appliance. By not changing the password from the default, the appliance will be subject to access by unauthorized individuals.'
  desc 'check', 'Have the System Administrator confirm the default SVAadmin password has been change from the default of "admin".

If the SVAadmin password has not been changed from the default of "admin", this is a finding.'
  desc 'fix', 'Following local password change procedures for Linux systems, change the SVAadmin password from the default of "admin".'
  impact 0.7
  ref 'DPMS Target McAfee MOVE Agentless 3.0 SVA'
  tag check_id: 'C-51549r1_chk'
  tag severity: 'high'
  tag gid: 'V-49679'
  tag rid: 'SV-62603r1_rule'
  tag stig_id: 'AV-MOVE-SVA-10'
  tag gtitle: 'AV-MOVE-SVA-10-McAfee MOVE SVAadmin password'
  tag fix_id: 'F-53181r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
