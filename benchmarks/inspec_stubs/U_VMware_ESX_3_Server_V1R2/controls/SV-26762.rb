control 'SV-26762' do
  title 'The SSH client must be configured to not allow X11 forwarding.'
  desc 'X11 forwarding over SSH allows for the secure remote execution of X11-based applications.  This feature can increase the attack surface of an SSH connection and should not be enabled unless needed.

If this function is necessary to support a valid mission requirement, its use must be authorized and approved in the system accreditation package.'
  desc 'check', "Check the SSH client configuration for the X11 forwarding setting.
# grep -i ForwardX11 /etc/ssh/ssh_config | grep -v '^#' 
If no lines are returned, or the returned setting has a value evaluating to yes, this is a finding."
  desc 'fix', 'Edit the SSH client configuration and change or add the ForwardX11 setting to no.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27771r1_chk'
  tag severity: 'low'
  tag gid: 'V-22469'
  tag rid: 'SV-26762r1_rule'
  tag stig_id: 'GEN005520'
  tag gtitle: 'GEN005520'
  tag fix_id: 'F-24012r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000221']
  tag nist: ['AC-4 (16)']
end
