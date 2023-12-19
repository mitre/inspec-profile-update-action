control 'SV-221696' do
  title 'The Oracle Linux operating system must not allow users to override SSH environment variables.'
  desc 'Failure to restrict system access to authenticated users negatively impacts operating system security.'
  desc 'check', 'Verify the operating system does not allow users to override environment variables to the SSH daemon.

Check for the value of the "PermitUserEnvironment" keyword with the following command:

# grep -i permituserenvironment /etc/ssh/sshd_config
PermitUserEnvironment no

If the "PermitUserEnvironment" keyword is not set to "no", is missing, or is commented out, this is a finding.'
  desc 'fix', 'Configure the operating system not to allow users to override environment variables to the SSH daemon.

Edit the "/etc/ssh/sshd_config" file to uncomment or add the line for "PermitUserEnvironment" keyword and set the value to "no":

PermitUserEnvironment no

The SSH service must be restarted for changes to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23411r419160_chk'
  tag severity: 'medium'
  tag gid: 'V-221696'
  tag rid: 'SV-221696r603260_rule'
  tag stig_id: 'OL07-00-010460'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-23400r419161_fix'
  tag 'documentable'
  tag legacy: ['V-99131', 'SV-108235']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
