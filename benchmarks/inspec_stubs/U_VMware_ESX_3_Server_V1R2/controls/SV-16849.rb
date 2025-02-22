control 'SV-16849' do
  title 'Virtual machine log files do not have a size limit.'
  desc 'Virtual machines can write troubleshooting information into a virtual machine log file (vmware.log) stored on the VMFS volume. Virtual machine users and processes may be configured to abuse the logging function, either intentionally or inadvertently so that large amounts of data flood the log file. Over time, the log file can consume so much of the ESX Server’s file system space that it fills the hard disk, causing an effective denial of service on the ESX Server.'
  desc 'check', '1. Login to VirtualCenter with the VI Client and select the virtual machine from the Inventory panel. 
The configuration page for the virtual machine appears with the Summary tab displayed.
2. Click Edit Settings.
3. Click Options > General and make a record of the path displayed in the virtual machine configuration file field. 
 
4. At the ESX Server service console, change directories to access the virtual machine configuration file recorded in step 3. 
5. Virtual machine configuration files are located in the /vmfs/volumes/(datastore) directory, where (datastore) is the name of the storage device on which the virtual machine files reside. In example above, [vol1]vm-finance/vm-finance.vmx is located in /vmfs/volumes/vol1/vm-finance/.
6. To verify the log size limit, perform the following:
# grep log.rotate.Size (virtual machine name).vmx  
log.rotateSize=(number in bytes)

If no limit is set, this is a finding.  The default is 500KB.'
  desc 'fix', 'Configure a limit for virtual machine log size.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16267r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15907'
  tag rid: 'SV-16849r1_rule'
  tag stig_id: 'ESX1110'
  tag gtitle: 'Virtual machine log files do not have size limit'
  tag fix_id: 'F-15868r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Machine Administrator]']
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
end
