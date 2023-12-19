control 'SV-26782' do
  title 'The SSH daemon must use privilege separation.'
  desc 'SSH daemon privilege separation causes the SSH process to drop root privileges when not needed, which would decrease the impact of software vulnerabilities in the unprivileged section.'
  desc 'check', "Check the SSH daemon configuration for the UsePrivilegeSeparation setting.
# grep -i UsePrivilegeSeparation  /etc/ssh/sshd_config | grep -v '^#' 
If the setting is not present, or not set to yes, this is a finding."
  desc 'fix', 'Edit the SSH daemon configuration and add or edit the UsePrivilegeSeparation setting value to yes.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27788r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22486'
  tag rid: 'SV-26782r1_rule'
  tag stig_id: 'GEN005537'
  tag gtitle: 'GEN005537'
  tag fix_id: 'F-24032r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
