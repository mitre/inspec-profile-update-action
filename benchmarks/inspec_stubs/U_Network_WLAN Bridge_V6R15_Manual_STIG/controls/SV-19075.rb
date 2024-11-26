control 'SV-19075' do
  title 'The network devices OOBM interface must be configured with an OOBM network address.'
  desc 'The OOBM access switch will connect to the management interface of the managed network device. The management interface of the managed network device will be directly connected to the OOBM network. An OOBM interface does not forward transit traffic; thereby, providing complete separation of production and management traffic. Since all management traffic is immediately forwarded into the management network, it is not exposed to possible tampering. The separation also ensures that congestion or failures in the managed network do not affect the management of the device. If the OOBM interface does not have an IP address from the managed network address space, it will not have reachability from the NOC using scalable and normal control plane and forwarding mechanisms.'
  desc 'check', 'Review the device configuration to determine if the OOB management interface is assigned an appropriate IP address from the authorized OOB management network.

If an IP address assigned to the interface is not from an authorized OOB management network, this is a finding.'
  desc 'fix', 'Configure the OOB management interface with an IP address from the address space belonging to the OOBM network.'
  impact 0.5
  ref 'DPMS Target WLAN Bridge'
  tag check_id: 'C-19238r5_chk'
  tag severity: 'medium'
  tag gid: 'V-17821'
  tag rid: 'SV-19075r4_rule'
  tag stig_id: 'NET0991'
  tag gtitle: 'The OOBM interface not configured correctly.'
  tag fix_id: 'F-17736r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
end
