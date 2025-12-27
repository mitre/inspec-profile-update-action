control 'SV-250676' do
  title 'The system must control virtual machine access to host resources.'
  desc "By default, all virtual machines on an ESXi host share the resources equally. By using the resource management capabilities of ESXi, such as shares and limits, you can control the server resources that a virtual machine consumes.  You can use this mechanism to prevent a denial of service that causes one virtual machine to consume so much of the host's resources that other virtual machines on the same host cannot perform their intended functions."
  desc 'check', "Virtual machines (VMs) that have a greater risk of being exploited or attacked, or that run applications known to potentially consume resources must be constrained. From the vSphere Client/vCenter, select the Datacenter/host. Right-click the VM, select Edit Settings to check the virtual machine's memory and/or CPU shares, limits, and/or reservation(s). Appropriate values must be set for memory, CPU, advanced CPU, and disk variables. Care must be taken to ensure that the settings do not hamper dynamic resource allocation and management proper to virtualization systems.

If any host VMs do not have share, limit, and/or reservation setpoints initialized, as appropriate to their respective levels of the risk of exploit or attack, this is a finding."
  desc 'fix', "From the vCenter client, select the Datacenter/host. Right-click the VM select Edit Settings to configure the virtual machine's memory and/or CPU limits, shares, and/or reservation(s). Appropriate values must be set for memory, CPU, advanced CPU, and disk variables. With the appropriate (site-specific) level selected for the VM, select the OK button to save any change(s)."
  impact 0.7
  ref 'DPMS Target VMware ESXi Version 5 Virtual Machine'
  tag check_id: 'C-54111r799488_chk'
  tag severity: 'high'
  tag gid: 'V-250676'
  tag rid: 'SV-250676r799490_rule'
  tag stig_id: 'ESXI5-VM-000001'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54065r799489_fix'
  tag 'documentable'
  tag legacy: ['V-39442', 'SV-51300']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
