control 'SV-78607' do
  title 'The system must disable shared salt values.'
  desc "When salting is enabled (Mem.ShareForceSalting=1 or 2) in order to share a page between two virtual machines both salt and the content of the page must be same. A salt value is a configurable VMX option for each virtual machine. You can manually specify the salt values in the virtual machine's VMX file with the new VMX option sched.mem.pshare.salt. If this option is not present in the virtual machine's VMX file, then the value of vc.uuid VMX option is taken as the default value. Since the vc.uuid is unique to each virtual machine, by default TPS happens only among the pages belonging to a particular virtual machine (Intra-VM)."
  desc 'check', 'From the vSphere Client select the Virtual Machine right click and go to Edit Settings >> VM Options Tab >> Advanced >> Configuration Parameters.  Verify the sched.mem.pshare.salt setting does not exist.

Note:  The VM must be powered off to view the advanced settings through the vSphere Client so it is recommended to view these settings with PowerCLI as it can be done while the VM is powered on.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name sched.mem.pshare.salt

If the virtual machine advanced setting sched.mem.pshare.salt exists, this is a finding.'
  desc 'fix', 'From a PowerCLI command prompt while connected to the ESXi host or vCenter server run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name sched.mem.pshare.salt | Remove-AdvancedSetting'
  impact 0.3
  ref 'DPMS Target VMware Virtual Machine 6.x'
  tag check_id: 'C-64867r1_chk'
  tag severity: 'low'
  tag gid: 'V-64117'
  tag rid: 'SV-78607r1_rule'
  tag stig_id: 'VMCH-06-000040'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-70045r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
