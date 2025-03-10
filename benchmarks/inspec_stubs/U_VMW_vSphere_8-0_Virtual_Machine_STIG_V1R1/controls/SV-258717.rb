control 'SV-258717' do
  title 'Virtual machines (VMs) must enable encryption for Fault Tolerance.'
  desc %q(Fault Tolerance log traffic can be encrypted. This could contain sensitive data from the protected machine's memory or CPU instructions.

vSphere Fault Tolerance performs frequent checks between a primary VM and secondary VM so the secondary VM can quickly resume from the last successful checkpoint. The checkpoint contains the VM state that has been modified since the previous checkpoint.

When Fault Tolerance is turned on, FT encryption is set to "Opportunistic" by default, which means it enables encryption only if both the primary and secondary host are capable of encryption.)
  desc 'check', 'If the Virtual Machine does not have Fault Tolerance enabled, this is not applicable.

For each virtual machine do the following:

From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> VM Options >> Encryption.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM | Where {($_.ExtensionData.Config.FtEncryptionMode -ne "ftEncryptionOpportunistic") -and ($_.ExtensionData.Config.FtEncryptionMode -ne "ftEncryptionRequired")}

If the "Encrypted FT" setting does not have a value of "Opportunistic" or "Required", this is a finding.'
  desc 'fix', 'For each virtual machine do the following:

From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> VM Options >> Encryption.

For "Encrypted FT" set the value to "Opportunistic" or "Required". Click "OK".

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following commands:

$spec = New-Object VMware.Vim.VirtualMachineConfigSpec
$spec.FTEncryption = New-Object VMware.Vim.VMware.Vim.VirtualMachineConfigSpecEncryptedFtModes
$spec.FT = ftEncryptionOpportunistic or ftEncryptionRequired
(Get-VM -Name <vmname>).ExtensionData.ReconfigVM($spec)'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 Virtual Machine'
  tag check_id: 'C-62457r933210_chk'
  tag severity: 'medium'
  tag gid: 'V-258717'
  tag rid: 'SV-258717r933212_rule'
  tag stig_id: 'VMCH-80-000204'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62366r933211_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
