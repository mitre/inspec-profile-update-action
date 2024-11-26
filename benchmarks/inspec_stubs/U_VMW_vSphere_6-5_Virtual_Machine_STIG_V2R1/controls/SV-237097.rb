control 'SV-237097' do
  title 'Shared salt values must be disabled on the virtual machine.'
  desc "When salting is enabled (Mem.ShareForceSalting=1 or 2) in order to share a page between two virtual machines both salt and the content of the page must be same. A salt value is a configurable advanced option for each virtual machine. You can manually specify the salt values in the virtual machine's advanced settings with the new option sched.mem.pshare.salt. If this option is not present in the virtual machine's advanced settings, then the value of the vc.uuid option is taken as the default value. Since the vc.uuid is unique to each virtual machine, by default TPS happens only among the pages belonging to a particular virtual machine (Intra-VM)."
  desc 'check', 'From the vSphere Web Client right-click the Virtual Machine and go to Edit Settings >> VM Options >> Advanced >> Configuration Parameters >> Edit Configuration. Verify the sched.mem.pshare.salt setting does not exist.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name sched.mem.pshare.salt

If the virtual machine advanced setting sched.mem.pshare.salt exists, this is a finding.'
  desc 'fix', 'From the vSphere Web Client right-click the Virtual Machine and go to Edit Settings >> VM Options >> Advanced >> Configuration Parameters >> Edit Configuration. Delete the sched.mem.pshare.salt setting.

Note: The VM must be powered off to configure the advanced settings through the vSphere Web Client so it is recommended to configure these settings with PowerCLI as it can be done while the VM is powered on. Settings do not take effect via either method until the virtual machine is cold started, not rebooted.

or
From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name sched.mem.pshare.salt | Remove-AdvancedSetting'
  impact 0.3
  ref 'DPMS Target VMware vSphere 6.5 Virtual Machine'
  tag check_id: 'C-40316r640126_chk'
  tag severity: 'low'
  tag gid: 'V-237097'
  tag rid: 'SV-237097r640128_rule'
  tag stig_id: 'VMCH-65-000040'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-40279r640127_fix'
  tag 'documentable'
  tag legacy: ['SV-104463', 'V-94633']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
