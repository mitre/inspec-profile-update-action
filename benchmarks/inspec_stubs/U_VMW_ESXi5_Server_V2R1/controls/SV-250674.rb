control 'SV-250674' do
  title 'The system must zero out VMDK files prior to deletion.'
  desc 'The virtual disk must be zeroed out prior to deletion in order to prevent sensitive data in VMDK files from being recovered.'
  desc 'check', 'Ask the SA if a documented procedure is used to overwrite sensitive data in VMDK flat files prior to deletion. The procedure must include a command to zero out data and the file must then be deleted. See some examples directly below.

vmkfstools --writezeroes <path+vmdk_flat_file>
or
dd if=/dev/zero of=<path+vmdk_flat_file>

If a documented procedure to overwrite sensitive data in VMDK flat files prior to deletion does not exist, this is a finding.'
  desc 'fix', 'Create and document a procedure to zero out sensitive data prior to removal of the VMDK file. Command line interface commands such as vmkfstools, dd, and rm must be used, per the examples below.

vmkfstools --writezeroes <path+vmdk_flat_file>
or
dd if=/dev/zero of=<path+vmdk_flat_file>

Note: The vSphere Client does not automatically zero out a VMDK file when it is destroyed.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54109r799019_chk'
  tag severity: 'medium'
  tag gid: 'V-250674'
  tag rid: 'SV-250674r799021_rule'
  tag stig_id: 'SRG-OS-99999-ESXI5-000161'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54063r799020_fix'
  tag 'documentable'
  tag legacy: ['SV-51211', 'V-39353']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
