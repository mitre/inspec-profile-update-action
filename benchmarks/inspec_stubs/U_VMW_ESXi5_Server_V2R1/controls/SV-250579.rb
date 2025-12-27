control 'SV-250579' do
  title 'The /etc/shells (or equivalent) file must exist.'
  desc 'The shells file (or equivalent) lists approved default shells. It helps provide layered defense to the security approach by ensuring users cannot change their default shell to an unauthorized shell that may not be secure.'
  desc 'check', 'Disable lock down mode. Enable the ESXi Shell.
<file> = /etc/shells
Execute the following command(s):
# ls -l /etc/shells

If /etc/shells does not exist, this is a finding.

Re-enable lock down mode.'
  desc 'fix', 'Disable lock down mode.
Enable the ESXi Shell.
<file> = /etc/shells
Execute the following command(s):
# > /etc/shells

Re-enable lock down mode.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54014r798734_chk'
  tag severity: 'medium'
  tag gid: 'V-250579'
  tag rid: 'SV-250579r798736_rule'
  tag stig_id: 'GEN002120-ESXI5-000045'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53968r798735_fix'
  tag 'documentable'
  tag legacy: ['V-39275', 'SV-51091']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
