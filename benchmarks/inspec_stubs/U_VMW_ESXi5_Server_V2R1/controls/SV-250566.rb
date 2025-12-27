control 'SV-250566' do
  title 'Spanning tree protocol must be enabled and BPDU guard and Portfast must be disabled on the upstream physical switch port for virtual machines that route or bridge traffic.'
  desc 'If an ESXi host guest VM is configured to perform a bridging function, the VM will generate BPDU frames to send out to the VDS. The VDS forwards the BPDU frames through the network adapter to the physical switch port. When the switch port configured with "BPDU guard" receives the BPDU frame, the switch will disable the port and the VM will lose connectivity. To avoid this network failure scenario while running a software-bridging function on an ESXi host, the "portfast" and "BPDU guard" configuration must be disabled on the port and spanning tree protocol must be enabled.'
  desc 'check', 'Organization and vendor specific check. Ask the SA if any ESXi host guest VM is configured to perform a bridging function. If any host VM is configured to perform a bridging function, ask the SA to confirm that port spanning tree protocol is enabled. Note that this check refers to an entity outside the scope of the ESXi server system.

If a guest VM is configured to perform a bridging function and spanning tree protocol is not enabled, this is a finding.'
  desc 'fix', 'Organization and vendor specific fix. If a guest VM is configured to perform a bridging function, enable spanning tree protocol for the VMs switch port. Note that this check refers to an entity outside the scope of the ESXi server system.'
  impact 0.3
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54001r798695_chk'
  tag severity: 'low'
  tag gid: 'V-250566'
  tag rid: 'SV-250566r798697_rule'
  tag stig_id: 'ESXI5-VMNET-000025'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53955r798696_fix'
  tag 'documentable'
  tag legacy: ['SV-51237', 'V-39379']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
