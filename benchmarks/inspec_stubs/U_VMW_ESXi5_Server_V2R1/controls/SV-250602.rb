control 'SV-250602' do
  title 'The SSH daemon must perform strict mode checking of home directory configuration files.'
  desc 'If other users have access to modify user-specific SSH configuration files, they may be able to log into the system as another user.'
  desc 'check', 'Disable lock down mode. Enable the ESXi Shell. Execute the following command(s):
# grep StrictModes /etc/ssh/sshd_config

If the command returns nothing, or the returned "StrictModes" attribute is set to "no", this is a finding.

Re-enable lock down mode.'
  desc 'fix', 'Disable lock down mode. Enable the ESXi Shell. Execute the following command(s):
# vi /etc/ssh/sshd_config

Add/modify the attribute line entry to the following (quotes for emphasis only):
"StrictModes yes"

Re-enable lock down mode.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54037r798803_chk'
  tag severity: 'medium'
  tag gid: 'V-250602'
  tag rid: 'SV-250602r798805_rule'
  tag stig_id: 'GEN005536-ESXI5-000110'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53991r798804_fix'
  tag 'documentable'
  tag legacy: ['SV-51278', 'V-39420']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
