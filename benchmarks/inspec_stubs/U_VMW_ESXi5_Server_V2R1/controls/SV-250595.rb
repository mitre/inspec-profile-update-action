control 'SV-250595' do
  title 'The SSH daemon must be configured to not allow X11 forwarding.'
  desc 'X11 forwarding over SSH allows for the secure remote execution of X11-based applications. This feature can increase the attack surface of an SSH connection and should not be enabled unless needed.'
  desc 'check', 'Disable lock down mode.
Enable the ESXi Shell. Check the SSH daemon configuration for the X11 forwarding setting. 

# grep -i "^X11Forwarding"  /etc/ssh/sshd_config

If "X11Forwarding" is set to "yes", this is a finding. 

Re-enable lock down mode.'
  desc 'fix', 'Disable lock down mode.
Enable the ESXi Shell.

Edit the SSH daemon configuration and add/modify the "X11Forwarding" configuration, setting it to "no". 
# vi /etc/ssh/sshd_config

Re-enable lock down mode.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54030r798782_chk'
  tag severity: 'medium'
  tag gid: 'V-250595'
  tag rid: 'SV-250595r798784_rule'
  tag stig_id: 'GEN005519-ESXI5-000102'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53984r798783_fix'
  tag 'documentable'
  tag legacy: ['V-39265', 'SV-51081']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
