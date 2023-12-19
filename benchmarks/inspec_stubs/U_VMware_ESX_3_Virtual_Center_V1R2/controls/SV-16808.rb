control 'SV-16808' do
  title 'VirtualCenter virtual machine CPU alarm is not configured.'
  desc 'To ensure that system administrators are notified if there is a resource problem on the VirtualCenter virtual machine, alarms should be configured to email the administrator. If alarms are not configured, system administrators will not be aware of any resource issues. If resources are unavailable on the VirtualCenter virtual machine, scheduled tasks may not be performed, and the potential denial of service on the VirtualCenter virtual machine.'
  desc 'check', '1. Log into VirtualCenter with the VI Client.
2. In the Inventory panel on the left, select the host that has the VirtualCenter virtual machine.
3. Click the Alarms tab.
4. To view alarms that have been defined, click Definitions.
    A list of defined alarms appears.  Double click an alarm definition to display Alarm settings dialog box and view.
If no Alarm exists that notifies the administrator when the VirtualCenter virtual machine CPU hits 90%, this is a finding.'
  desc 'fix', 'Configure an alarm to notify the administrator when the VirtualCenter CPU hits 90%.'
  impact 0.3
  ref 'DPMS Target VMware VirtualCenter'
  tag check_id: 'C-16224r1_chk'
  tag severity: 'low'
  tag gid: 'V-15867'
  tag rid: 'SV-16808r1_rule'
  tag stig_id: 'ESX0680'
  tag gtitle: 'VirtualCenter virtual machine has no CPU alarm.'
  tag fix_id: 'F-15827r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
