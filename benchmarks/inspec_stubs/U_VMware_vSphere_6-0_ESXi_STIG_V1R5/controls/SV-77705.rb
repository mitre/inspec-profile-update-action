control 'SV-77705' do
  title 'The SSH daemon must be configured to not allow X11 forwarding.'
  desc 'X11 forwarding over SSH allows for the secure remote execution of X11-based applications. This feature can increase the attack surface of an SSH connection.'
  desc 'check', 'To verify the X11Forwarding setting, run the following command: 

# grep -i "^X11Forwarding" /etc/ssh/sshd_config

If there is no output or the output is not exactly "X11Forwarding no", this is a finding.'
  desc 'fix', 'To set the X11Forwarding setting, add or correct the following line in "/etc/ssh/sshd_config":

X11Forwarding no'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-63949r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63215'
  tag rid: 'SV-77705r1_rule'
  tag stig_id: 'ESXI-06-000023'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-69133r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
