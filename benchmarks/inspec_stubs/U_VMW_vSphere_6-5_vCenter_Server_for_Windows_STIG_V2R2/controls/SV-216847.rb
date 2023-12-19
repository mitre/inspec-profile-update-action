control 'SV-216847' do
  title 'The vCenter Server for Windows must disable the managed object browser at all times, when not required for the purpose of troubleshooting or maintenance of managed objects.'
  desc 'The managed object browser provides a way to explore the object model used by the vCenter to manage the vSphere environment; it enables configurations to be changed as well. This interface is used primarily for debugging, and might potentially be used to perform malicious configuration changes or actions.'
  desc 'check', %q(The Managed Object Browser (MOB) was designed to be used by SDK developers to assist in the development, programming, and debugging of objects. It is an inventory object, full-access interface, allowing attackers to determine the inventory path of an infrastructure's managed entities. 

Check the operational status of the MOB:
Determine the location of the vpxd.cfg file on the vCenter Server's Windows OS host.
Edit the file and locate the <vpxd> ... </vpxd> element.
Ensure the following element is set. <enableDebugBrowse>false</enableDebugBrowse> 

If the MOB is currently enabled, ask the SA if it is being used for object maintenance. 

If the "enableDebugBrowse" element is enabled (set to true), and object maintenance is not being performed, this is a finding.)
  desc 'fix', 'If the datastore browser is enabled and required for object maintenance, no fix is immediately required.

Disable the managed object browser:
Determine the location of the vpxd.cfg file on the Windows host.
Edit the file and locate the <vpxd> ... </vpxd> element.
Ensure the following element is set. <enableDebugBrowse>false</enableDebugBrowse> 

Restart the vCenter Service to ensure the configuration file change(s) are in effect.'
  impact 0.3
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18078r366255_chk'
  tag severity: 'low'
  tag gid: 'V-216847'
  tag rid: 'SV-216847r612237_rule'
  tag stig_id: 'VCWN-65-000025'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-18076r366256_fix'
  tag 'documentable'
  tag legacy: ['SV-104591', 'V-94761']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
