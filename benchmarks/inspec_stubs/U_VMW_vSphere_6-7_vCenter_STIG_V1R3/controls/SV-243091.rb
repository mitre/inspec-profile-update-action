control 'SV-243091' do
  title 'The vCenter Server must disable the managed object browser (MOB) at all times when not required for troubleshooting or maintenance of managed objects.'
  desc "The MOB was designed to be used by SDK developers to assist in the development, programming, and debugging of objects. It is an inventory object, full-access interface, allowing attackers to determine the inventory path of an infrastructure's managed entities.

The MOB provides a way to explore the object model used by the vCenter to manage the vSphere environment; it enables configurations to be changed as well. This interface is used primarily for debugging and could potentially be used to perform malicious configuration changes or actions."
  desc 'check', 'Check the operational status of the MOB by performing one of the following or both:

Browse to the MOB page on the vCenter server:

https://<vcenter fqdn or IP>/mob

If a "503 Service Unavailable" error is returned, the MOB is disabled. 

If a prompt for authentication appears, it is enabled.

or

Run the following command from the vCenter appliance:

grep -i "enableDebugBrowse" /etc/vmware-vpx/vpxd.cfg

If the MOB is enabled, ask the SA if it is being used for object maintenance and if so, this is not a finding. 

If the "enableDebugBrowse" element is enabled (set to true) or absent, and object maintenance is not being performed, this is a finding.'
  desc 'fix', 'If the datastore browser is enabled and required for object maintenance, no fix is immediately required.

Disable the managed object browser by editing the /etc/vmware-vpx/vpxd.cfg file.

Edit the file and locate the <vpxd> ... </vpxd> element.

Add or update the following element in the vpxd section:
 <enableDebugBrowse>false</enableDebugBrowse>

Note: It is not present by default and is case sensitive.

Restart the vCenter Service to ensure the configuration file change(s) are in effect by running the following command on the vCenter appliance:

service-control --restart vmware-vpxd'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46366r719514_chk'
  tag severity: 'medium'
  tag gid: 'V-243091'
  tag rid: 'SV-243091r719516_rule'
  tag stig_id: 'VCTR-67-000025'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-46323r719515_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
