control 'SV-250590' do
  title 'The SSH client must be configured to only use the SSHv2 protocol.'
  desc 'SSHv1 is not a DoD-approved protocol and has many well-known vulnerability exploits. Exploits of the SSH client could provide access to the system with the privileges of the user running the client.'
  desc 'check', %q(Disable lock down mode.
Enable the ESXi Shell.

Check the SSH client configuration for required protocol. # grep -i "Protocol 2" /etc/ssh/ssh_config | grep -v '^#' 

Re-enable lock down mode.

If the returned protocol list contains anything except 2, this is a finding. If the /etc/ssh/ssh_config file does not exist or the Protocol option is not set, this is not a finding because the SSH client cannot enforce the Protocol setting on a compliant SSH server.)
  desc 'fix', 'Disable lock down mode.
Enable the ESXi Shell.

Edit the SSH client  configuration and add/modify the "Protocol" configuration for Protocol 2 only. 
# vi /etc/ssh/ssh_config

Re-enable lock down mode.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54025r798767_chk'
  tag severity: 'medium'
  tag gid: 'V-250590'
  tag rid: 'SV-250590r798769_rule'
  tag stig_id: 'GEN005501-ESXI5-9778'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53979r798768_fix'
  tag 'documentable'
  tag legacy: ['SV-51272', 'V-39414']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
