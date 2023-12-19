control 'SV-215300' do
  title 'AIX must turn off X11 forwarding for the SSH daemon.'
  desc 'X11 forwarding over SSH allows for the secure remote execution of X11-based applications. This feature can increase the attack surface of an SSH connection and should not be enabled unless needed.'
  desc 'check', %q(If X11 forwarding has been authorized for use, this is Not Applicable.

Check the SSH daemon configuration for the "X11Forwarding" directive using command: 

# grep -i X11Forwarding /etc/ssh/sshd_config | grep -v '^#' 
X11Forwarding no

If the setting is not present or the setting is "yes", this is a finding.)
  desc 'fix', 'Edit the "/etc/sshd/sshd_config" file to add the following line and save the change:
X11Forwarding no

Restart the SSH daemon:
# stopsrc -s sshd
# startsrc -s sshd'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16498r294351_chk'
  tag severity: 'medium'
  tag gid: 'V-215300'
  tag rid: 'SV-215300r508663_rule'
  tag stig_id: 'AIX7-00-002117'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16496r294352_fix'
  tag 'documentable'
  tag legacy: ['V-91731', 'SV-101829']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
