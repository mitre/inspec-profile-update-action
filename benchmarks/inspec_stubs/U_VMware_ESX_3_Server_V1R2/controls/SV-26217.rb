control 'SV-26217' do
  title 'The IPv6 protocol handler must be prevented from dynamic loading unless needed.'
  desc 'IPv6 is the next generation of the Internet protocol.  Binding this protocol to the network stack increases the attack surface of the host.   Unprivileged local processes may be able to cause the system to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', 'If the system uses IPv6, this is not applicable.
Determine if the IPv6 protocol handler is prevented from dynamic loading.  If it is not, this is a finding.'
  desc 'fix', 'Configure the system to prevent the dynamic loading of the IPv6 protocol handler.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29297r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22542'
  tag rid: 'SV-26217r1_rule'
  tag stig_id: 'GEN007720'
  tag gtitle: 'GEN007720'
  tag fix_id: 'F-26329r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
