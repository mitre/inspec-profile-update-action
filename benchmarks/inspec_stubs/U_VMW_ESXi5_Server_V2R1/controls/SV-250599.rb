control 'SV-250599' do
  title 'The SSH daemon must not permit user environment settings.'
  desc 'SSH may be used to provide limited functions other than an interactive shell session, such as file transfer. If local, user-defined environment settings (such as, those configured in ~/.ssh/authorized_keys and ~/.ssh/environment) are configured by the user and permitted by the SSH daemon, they could be used to alter the behavior of the limited functions, potentially granting unauthorized access to the system.'
  desc 'check', 'Disable lock down mode. Enable the ESXi Shell. Execute the following command(s):
# grep PermitUserEnvironment /etc/ssh/sshd_config

If the command returns nothing, or the returned "PermitUserEnvironment" attribute is not set to "no", this is a finding.

Re-enable lock down mode.'
  desc 'fix', 'Disable lock down mode. Enable the ESXi Shell. Execute the following command(s):
# vi /etc/ssh/sshd_config

Add/modify the attribute line entry to the following (quotes for emphasis only):
"PermitUserEnvironment no"

Re-enable lock down mode.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54034r798794_chk'
  tag severity: 'medium'
  tag gid: 'V-250599'
  tag rid: 'SV-250599r798796_rule'
  tag stig_id: 'GEN005530-ESXI5-000107'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53988r798795_fix'
  tag 'documentable'
  tag legacy: ['V-39267', 'SV-51083']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
