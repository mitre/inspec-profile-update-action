control 'SV-250630' do
  title 'The SSH daemon must be configured to only use the SSHv2 protocol.'
  desc 'SSHv1 is not a DoD-approved protocol and has many well-known vulnerability exploits. Exploits of the SSH daemon could provide immediate root access to the system.'
  desc 'check', %q(Disable lock down mode.
Enable the ESXi Shell.

Check the SSH daemon configuration for required protocol. # grep -i "Protocol 2" /etc/ssh/sshd_config | grep -v '^#' 

Re-enable lock down mode.

If no lines are returned, or the returned protocol list contains anything except 2, this is a finding.)
  desc 'fix', 'Disable lock down mode.
Enable the ESXi Shell.

Edit the SSH daemon configuration and add/modify the "Protocol" configuration for Protocol 2 only. 
# vi /etc/ssh/sshd_config

Re-enable lock down mode.'
  impact 0.7
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54065r798887_chk'
  tag severity: 'high'
  tag gid: 'V-250630'
  tag rid: 'SV-250630r798889_rule'
  tag stig_id: 'SRG-OS-000112-ESXI5'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54019r798888_fix'
  tag 'documentable'
  tag legacy: ['SV-51270', 'V-39412']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
