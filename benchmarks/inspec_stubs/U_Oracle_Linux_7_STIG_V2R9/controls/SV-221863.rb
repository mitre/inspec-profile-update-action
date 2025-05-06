control 'SV-221863' do
  title 'The Oracle Linux operating system must be configured so that the SSH daemon uses privilege separation.'
  desc 'SSH daemon privilege separation causes the SSH process to drop root privileges when not needed, which would decrease the impact of software vulnerabilities in the unprivileged section.'
  desc 'check', 'Verify the SSH daemon performs privilege separation.

Check that the SSH daemon performs privilege separation with the following command:

# grep -i usepriv /etc/ssh/sshd_config

UsePrivilegeSeparation sandbox

If the "UsePrivilegeSeparation" keyword is set to "no", is missing, or the returned line is commented out, this is a finding.'
  desc 'fix', 'Uncomment the "UsePrivilegeSeparation" keyword in "/etc/ssh/sshd_config" (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor) and set the value to "sandbox" or "yes":

UsePrivilegeSeparation sandbox

The SSH service must be restarted for changes to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23578r419661_chk'
  tag severity: 'medium'
  tag gid: 'V-221863'
  tag rid: 'SV-221863r603260_rule'
  tag stig_id: 'OL07-00-040460'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23567r419662_fix'
  tag 'documentable'
  tag legacy: ['V-99465', 'SV-108569']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
