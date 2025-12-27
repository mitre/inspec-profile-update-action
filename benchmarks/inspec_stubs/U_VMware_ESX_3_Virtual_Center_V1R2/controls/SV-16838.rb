control 'SV-16838' do
  title 'Configuration tools are enabled for virtual machines.'
  desc 'There are other settings that should be specified in the configuration files for virtual machines. The connectable setting disables connecting and disconnecting removable devices from within the virtual machine. The diskShrink setting shrinks the virtual disk. The diskWiper defragments virtual disks.  These last two settings could effectively cause a DoS by having the virtual disk defragmented and shrunk on demand.
The commands that should be disabled are listed:

isolation.device.connectable.disable = “TRUE”
isolation.tools.diskShrink.disable = “TRUE”
isolation.tools.diskWiper.disable = “TRUE”'
  desc 'check', '1. Login to VirtualCenter with the VI Client and select a virtual machine from the inventory panel.
The configuration page for the virtual machine appears with the Summary tab displayed.
3. Click Options > Advanced > Configuration Parameters to open the Configuration Parameters dialog box.
4. Verify the following is displayed in the result:

isolation.device.connectable.disable    	true
isolation.tools.diskShrink.disable     	 	    true
isolation.tools.diskWiper.disable     		    true


If these are not configured, this is a finding.'
  desc 'fix', 'Disable configuration tools for the virtual machine.'
  impact 0.3
  ref 'DPMS Target VMware VirtualCenter'
  tag check_id: 'C-16256r1_chk'
  tag severity: 'low'
  tag gid: 'V-15896'
  tag rid: 'SV-16838r1_rule'
  tag stig_id: 'ESX1000'
  tag gtitle: 'Configuration tools are enabled'
  tag fix_id: 'F-15857r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Machine Administrator]']
  tag ia_controls: 'ECSC-1'
end
