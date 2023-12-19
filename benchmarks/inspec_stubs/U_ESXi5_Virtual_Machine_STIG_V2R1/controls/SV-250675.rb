control 'SV-250675' do
  title 'The system must disable VM logging, unless required.'
  desc 'Excessive VM logging may degrade system performance. The following settings can be used to limit the total size and number of log files. Normally a new log file is created only when a host is rebooted, so the file can grow to be quite large. Ensure new log files are created more frequently by limiting the maximum size of the log files. To restrict the total size of logging data, VMware recommends saving 10 log files, each one limited to 1,000KB. Datastores are likely to be formatted with a block size of 2MB or 4MB, so a size limit too far below this size would result in unnecessary storage utilization. Each time an entry is written to the log, the size of the log is checked; if it is over the limit, the next entry is written to a new log. If the maximum number of log files already exists, when a new one is created, the oldest log file is deleted. A denial-of-service attack that avoids these limits might be attempted by writing an enormous log entry. But each log entry is limited to 4KB, so no log files are ever more than 4KB larger than the configured limit. A second option is to disable logging for the virtual machine. Disabling logging for a virtual machine makes troubleshooting challenging and support difficult. Do not consider disabling logging unless the log file rotation approach proves insufficient. Uncontrolled logging can lead to denial-of-service due to the datastore becoming filled.'
  desc 'check', %q(If VM log file rotation is not degrading system performance and the VM requires logging to be enabled for troubleshooting, this check is not applicable.

Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. 

Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. 
If connecting to vCenter Server, click on the desired host. 
Click the Configuration tab. 
Click Software, Security Profile, Services, Properties, ESXi Shell, and Options, respectively.
Start the ESXi Shell service, where/as required.

As root, log in to the ESXi Shell and locate the VM's vmx file.
# find / | grep vmx

Check the VM's ".vmx" file for the correct "<keyword> = <keyval>" pair.
keyword = logging
keyval = FALSE
# grep "^<keyword>" <the VM's vmx file>

If the logging keyword is set to "TRUE", this is a finding.

Re-enable Lockdown Mode on the host.)
  desc 'fix', %q(VM logging should be disabled by default, unless required for troubleshooting. To disable logging for a VM with logging enabled, configure the VM with the correct "<keyword> = <keyval>" pair. 

To edit a powered-down virtual machine's .vmx file, first remove it from vCenter Server's inventory. Manual additions to the .vmx file from ESXi will be overwritten by any registered entries stored in the vCenter Server database. Make a backup copy of the .vmx file. If the edit breaks the virtual machine, it can be rolled back to the original version of the file. 

Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. 
If connecting to vCenter Server, click on the desired host. 
Click the Configuration tab. 
Click Storage. 
Right-click on the appropriate datastore and click Browse Datastore. 
Navigate to the folder named after the virtual machine, and locate the <virtual machine>.vmx file. 
Right-click the .vmx file and click Remove from inventory.

Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. 

Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. 
If connecting to vCenter Server, click on the desired host. 
Click the Configuration tab. 
Click Software, Security Profile, Services, Properties, ESXi Shell, and Options, respectively.
Start the ESXi Shell service, where/as required.

As root, log in to the ESXi host and locate the VM's vmx file. 
# find / | grep vmx

Add the following to the VM's vmx file.
keyword = "keyval"

Where:
keyword = logging
keyval = FALSE

Re-enable Lockdown Mode on the host.

Re-register the VM with the vCenter Server:
Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. 
If connecting to vCenter Server, click on the desired host. 
Click the Configuration tab. 
Click Storage. 
Right-click on the appropriate datastore and click Browse Datastore. 
Navigate to the folder named after the virtual machine, and locate the <virtual machine>.vmx file. 
Right-click the .vmx file and click Add to inventory. The Add to Inventory wizard opens. 
Continue to follow the wizard to add the virtual machine.)
  impact 0.5
  ref 'DPMS Target VMware ESXi Version 5 Virtual Machine'
  tag check_id: 'C-54110r799485_chk'
  tag severity: 'medium'
  tag gid: 'V-250675'
  tag rid: 'SV-250675r799487_rule'
  tag stig_id: 'ESXI5-VM-000012'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54064r799486_fix'
  tag 'documentable'
  tag legacy: ['SV-51311', 'V-39453']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
