control 'SV-26214' do
  title 'The Bluetooth protocol handler must be disabled or not installed.'
  desc 'Bluetooth is a Personal Area Network (PAN) technology.  Binding this protocol to the network stack increases the attack surface of the host.   Unprivileged local processes may be able to cause the kernel to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', 'If there is no Bluetooth protocol handler for the system, this is not applicable.

Determine if the system prevents the dynamic loading of the Bluetooth protocol handler. If it does not, this is a finding.'
  desc 'fix', 'Configure the system to prevent the dynamic loading of the Bluetooth protocol handler.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29137r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22539'
  tag rid: 'SV-26214r1_rule'
  tag stig_id: 'GEN007660'
  tag gtitle: 'GEN007660'
  tag fix_id: 'F-26143r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
