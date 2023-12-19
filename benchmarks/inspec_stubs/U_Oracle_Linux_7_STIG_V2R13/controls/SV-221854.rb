control 'SV-221854' do
  title 'The Oracle Linux operating system must not permit direct logons to the root account using remote access via SSH.'
  desc 'Even though the communications channel may be encrypted, an additional layer of security is gained by extending the policy of not logging on directly as root. In addition, logging on with a user-specific account provides individual accountability of actions performed on the system.'
  desc 'check', 'Verify remote access using SSH prevents users from logging on directly as root.

Check that SSH prevents users from logging on directly as root with the following command:

# grep -i permitrootlogin /etc/ssh/sshd_config
PermitRootLogin no

If the "PermitRootLogin" keyword is set to "yes", is missing, or is commented out, this is a finding.'
  desc 'fix', 'Configure SSH to stop users from logging on remotely as the root user.

Edit the appropriate "/etc/ssh/sshd_config" file to uncomment or add the line for the "PermitRootLogin" keyword and set its value to "no" (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor):

PermitRootLogin no

The SSH service must be restarted for changes to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23569r419634_chk'
  tag severity: 'medium'
  tag gid: 'V-221854'
  tag rid: 'SV-221854r603260_rule'
  tag stig_id: 'OL07-00-040370'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23558r419635_fix'
  tag 'documentable'
  tag legacy: ['V-99447', 'SV-108551']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
