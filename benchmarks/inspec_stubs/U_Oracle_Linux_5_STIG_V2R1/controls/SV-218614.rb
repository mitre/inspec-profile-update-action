control 'SV-218614' do
  title 'The SSH daemon must use privilege separation.'
  desc 'SSH daemon privilege separation causes the SSH process to drop root privileges when not needed, which would decrease the impact of software vulnerabilities in the unprivileged section.'
  desc 'check', %q(Check the SSH daemon configuration for the UsePrivilegeSeparation setting.

# grep -i UsePrivilegeSeparation /etc/ssh/sshd_config | grep -v '^#'
 
If the setting is not present, or not set to "yes", this is a finding.)
  desc 'fix', 'Edit the SSH daemon configuration and add or edit the "UsePrivilegeSeparation" setting value to "yes".   

Restart the SSH daemon.
# /sbin/service sshd restart'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20089r556040_chk'
  tag severity: 'medium'
  tag gid: 'V-218614'
  tag rid: 'SV-218614r603259_rule'
  tag stig_id: 'GEN005537'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20087r556041_fix'
  tag 'documentable'
  tag legacy: ['V-22486', 'SV-64073']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
