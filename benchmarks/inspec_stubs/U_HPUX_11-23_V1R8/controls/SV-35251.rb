control 'SV-35251' do
  title 'The Bluetooth protocol handler must be disabled or not installed.'
  desc 'Bluetooth is a Personal Area Network (PAN) technology.  Binding this protocol to the network stack increases the attack surface of the host.   Unprivileged local processes may be able to cause the kernel to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', 'If there is no Bluetooth protocol handler for the system, this is not applicable.

The Bluetooth protocol handler is not currently available for the HP-UX 11i platform and is therefore not applicable.'
  desc 'fix', 'Configure the system to prevent the dynamic loading of the Bluetooth protocol handler.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-35113r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22539'
  tag rid: 'SV-35251r1_rule'
  tag stig_id: 'GEN007660'
  tag gtitle: 'GEN007660'
  tag fix_id: 'F-26143r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
