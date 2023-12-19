control 'SV-26773' do
  title 'The SSH daemon must not permit user environment settings.'
  desc 'SSH may be used to provide limited functions other than an interactive shell session, such as file transfer.  If local, user-defined environment settings (such as, those configured in ~/.ssh/authorized_keys and ~/.ssh/environment) are configured by the user and permitted by the SSH daemon, they could be used to alter the behavior of the limited functions, potentially granting unauthorized access to the system.'
  desc 'check', 'Check the PermitUserEnvironment setting in the SSH daemon configuration.

Procedure:
# grep -i PermitUserEnvironment sshd_config

If the setting is not present or set to a value other than no, this is a finding.'
  desc 'fix', 'Edit the SSH daemon configuration and edit (or add) the PermitUserEnvironment setting with a value of no.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27781r1_chk'
  tag severity: 'low'
  tag gid: 'V-22479'
  tag rid: 'SV-26773r1_rule'
  tag stig_id: 'GEN005530'
  tag gtitle: 'GEN005530'
  tag fix_id: 'F-24023r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000221']
  tag nist: ['AC-4 (16)']
end
