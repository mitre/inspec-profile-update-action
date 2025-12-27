control 'SV-26218' do
  title 'The IPv6 protocol handler must not be installed unless needed.'
  desc 'IPv6 is the next generation of the Internet protocol.  Binding this protocol to the network stack increases the attack surface of the host.   Unprivileged local processes may be able to cause the kernel to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', 'If the IPv6 protocol handler is not available as an optional software package for the system, this is not applicable.
If the system uses IPv6, this is not applicable.
If the IPv6 protocol handler is installed, this is a finding.'
  desc 'fix', 'Uninstall the IPv6 protocol handler from the system.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29298r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22543'
  tag rid: 'SV-26218r2_rule'
  tag stig_id: 'GEN007740'
  tag gtitle: 'GEN007740'
  tag fix_id: 'F-26330r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
