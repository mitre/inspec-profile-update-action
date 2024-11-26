control 'SV-207624' do
  title 'The ESXi host SSH daemon must be configured to not allow X11 forwarding.'
  desc 'X11 forwarding over SSH allows for the secure remote execution of X11-based applications. This feature can increase the attack surface of an SSH connection.'
  desc 'check', 'From an SSH session connected to the ESXi host, or from the ESXi shell, run the following command:

# grep -i "^X11Forwarding" /etc/ssh/sshd_config

If there is no output or the output is not exactly "X11Forwarding no", this is a finding.'
  desc 'fix', 'From an SSH session connected to the ESXi host, or from the ESXi shell, add or correct the following line in "/etc/ssh/sshd_config":

X11Forwarding no'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7879r364271_chk'
  tag severity: 'medium'
  tag gid: 'V-207624'
  tag rid: 'SV-207624r388482_rule'
  tag stig_id: 'ESXI-65-000023'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-7879r364272_fix'
  tag 'documentable'
  tag legacy: ['SV-104079', 'V-93993']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
