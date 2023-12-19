control 'SV-250596' do
  title 'The SSH client must be configured to not allow X11 forwarding.'
  desc 'X11 forwarding over SSH allows for the secure remote execution of X11-based applications. This feature can increase the attack surface of an SSH connection and should not be enabled unless needed.'
  desc 'check', 'Disable lock down mode.
Enable the ESXi Shell. Check the SSH client configuration for the X11 forwarding setting. # grep -i "^ForwardX11"  /etc/ssh/ssh_config

If "ForwardX11" is set to "yes", this is a finding. If the /etc/ssh/ssh_config file does not exist or the ForwardX11 option is not set, this is not a finding.

Re-enable lock down mode.'
  desc 'fix', 'Disable lock down mode.
Enable the ESXi Shell.

Edit the SSH client configuration and add/modify the "ForwardX11" configuration to "no". 
# vi /etc/ssh/ssh_config

Re-enable lock down mode.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54031r798785_chk'
  tag severity: 'medium'
  tag gid: 'V-250596'
  tag rid: 'SV-250596r798787_rule'
  tag stig_id: 'GEN005520-ESXI5-705'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53985r798786_fix'
  tag 'documentable'
  tag legacy: ['SV-51087', 'V-39271']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
