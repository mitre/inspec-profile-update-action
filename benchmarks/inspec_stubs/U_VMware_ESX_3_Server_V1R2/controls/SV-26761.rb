control 'SV-26761' do
  title 'The SSH daemon must be configured to not allow X11 forwarding.'
  desc 'X11 forwarding over SSH allows for the secure remote execution of X11-based applications.  This feature can increase the attack surface of an SSH connection and should not be enabled unless needed.

If this function is necessary to support a valid mission requirement, its use must be authorized and approved in the system accreditation package.'
  desc 'check', "Check the SSH daemon configuration for the X11 forwarding setting.
# grep -i X11Forwarding /etc/ssh/sshd_config | grep -v '^#' 
If no lines are returned, or the returned setting has a value evaluating to yes, this is a finding."
  desc 'fix', 'Edit the SSH daemon configuration and change or add the X11Forwarding setting to no.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27770r1_chk'
  tag severity: 'low'
  tag gid: 'V-22468'
  tag rid: 'SV-26761r1_rule'
  tag stig_id: 'GEN005519'
  tag gtitle: 'GEN005519'
  tag fix_id: 'F-24011r1_fix'
  tag 'documentable'
  tag mitigations: 'GEN005519'
  tag mitigation_control: 'If X11 connection forwarding is required, the risk of unauthorized use of this feature can be mitigated by placing restrictions on which users are permitted to use it. For instance, OpenSSH provides conditional configuration blocks (using the Match keyword) used to limit X11 connection forwarding based on user, group, host, or address.'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000221']
  tag nist: ['AC-4 (16)']
end
