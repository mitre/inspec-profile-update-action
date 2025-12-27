control 'SV-35247' do
  title 'The DECnet protocol must be disabled or not installed.'
  desc 'The DECnet suite of protocols is no longer commonly used.  Binding this protocol to the network stack increases the attack surface of the host.  Unprivileged local processes may be able to cause the system to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', 'If there is no DECnet protocol handler for the system, this is not applicable.

The DECnet protocol handler is not currently available for the HP-UX 11i platform and is therefore not applicable.'
  desc 'fix', 'Configure the system to not dynamically load the DECnet protocol handler.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-35110r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22527'
  tag rid: 'SV-35247r1_rule'
  tag stig_id: 'GEN007320'
  tag gtitle: 'GEN007320'
  tag fix_id: 'F-30376r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
