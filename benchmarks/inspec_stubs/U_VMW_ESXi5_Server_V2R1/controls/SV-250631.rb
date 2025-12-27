control 'SV-250631' do
  title 'The operating system must use organization-defined replay-resistant authentication mechanisms for network access to non-privileged accounts.'
  desc 'An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message. 

Techniques used to address this include protocols using challenges (e.g., TLS, WS_Security), time synchronous, or challenge-response one-time authenticators.'
  desc 'check', %q(Disable lock down mode.
Enable the ESXi Shell.

Check the SSH client configuration for required protocol. # grep -i "Protocol 2" /etc/ssh/ssh_config | grep -v '^#' 

Re-enable lock down mode.

If the returned protocol list contains anything except 2, this is a finding. If the /etc/ssh/ssh_config file does not exist or the Protocol option is not set, this is not a finding.)
  desc 'fix', 'Disable lock down mode.
Enable the ESXi Shell.

Edit the SSH client  configuration and add/modify the "Protocol" configuration for Protocol 2 only. 
# vi /etc/ssh/ssh_config

Re-enable lock down mode.'
  impact 0.7
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54066r798890_chk'
  tag severity: 'high'
  tag gid: 'V-250631'
  tag rid: 'SV-250631r798892_rule'
  tag stig_id: 'SRG-OS-000113-ESXI5'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54020r798891_fix'
  tag 'documentable'
  tag legacy: ['V-39413', 'SV-51271']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
