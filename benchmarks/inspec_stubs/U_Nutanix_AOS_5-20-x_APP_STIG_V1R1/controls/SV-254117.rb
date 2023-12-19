control 'SV-254117' do
  title 'Nutanix AOS must separate hosted application functionality from application server management functionality.'
  desc 'The application server consists of the management interface and hosted applications. By separating the management interface from hosted applications, the user must authenticate as a privileged user to the management interface before being presented with management functionality. This prevents nonprivileged users from having visibility to functions not available to the user. By limiting visibility, a compromised nonprivileged account does not offer information to the attacker to functionality and information needed to further the attack on the application server.

Application server management functionality includes functions necessary to administer the application server and requires privileged access via one of the accounts assigned to a management role. The hosted application and hosted application functionality consists of the assets needed for the application to function, such as the business logic, databases, user authentication, etc.

The separation of application server administration functionality from hosted application functionality is either physical or logical and is accomplished by using different computers, different central processing units, different instances of the operating system, network addresses, network ports, or combinations of these methods, as appropriate.'
  desc 'check', 'Management information flow can be isolated to a separate vLAN from the guest VMs.
1. Log in to Prism Element.
2. Click on the gear icon in the upper right corner.
3. Under the "Settings" menu click "Network Configuration", and then select the "Internal Interfaces" tab.
4. Click on the "Management LAN" option.

If VLAN ID is "0" or blank, this is a finding.'
  desc 'fix', '1. Log in to Prism Element.
2. Click on the gear icon in the upper right corner.
3. Under the "Settings" menu click "Network Configuration", and then select the "Internal Interfaces" tab.
4. Click the "Management LAN" option.
5. Set the VLAN to the VLAN used for management functions.

SSH into each CVM host as user nutanix and issue the following command: change_cvm_vlan vlan_id.
SSH into each AHV host as root and issue the following command: ovs-vsctl set port br0 tag=vlan_id
Note: Network switches connected to all Nutanix nodes must be appropriately configured with the same vlan_id.'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x Application'
  tag check_id: 'C-57602r846437_chk'
  tag severity: 'medium'
  tag gid: 'V-254117'
  tag rid: 'SV-254117r846439_rule'
  tag stig_id: 'NUTX-AP-000890'
  tag gtitle: 'SRG-APP-000211-AS-000146'
  tag fix_id: 'F-57553r846438_fix'
  tag 'documentable'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
