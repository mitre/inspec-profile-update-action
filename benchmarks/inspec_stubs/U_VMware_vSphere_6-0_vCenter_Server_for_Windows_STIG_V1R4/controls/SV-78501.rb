control 'SV-78501' do
  title 'vSphere Client plugins must be verified.'
  desc 'The vCenter Server includes a vSphere Client extensibility framework, which provides the ability to extend the vSphere Client with menu selections or toolbar icons that provide access to vCenter Server add-on components or external, Web-based functionality. vSphere Client plugins or extensions run at the same privilege level as the user. Malicious extensions might masquerade as useful add-ons while compromising the system by stealing credentials or incorrectly configuring the system.'
  desc 'check', 'Verify the vSphere Client used by administrators includes only authorized extensions from trusted sources.

From the vSphere Web Client go to Administration >> Client Plug-Ins. View the Installed/Available Plug-ins list and verify they are all identified as authorized VMware, 3rd party (Partner) and/or site-specific (locally developed and site) approved plug-ins.

If any Installed/Available plug-ins in the viewable list cannot be verified as vSphere Client plug-ins and/or authorized extensions from trusted sources, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Administration >> Client Plug-Ins and right click the unknown plug-in and click disable then proceed to remove the plug-in.

To remove plug-ins do the following:

If you have vCenter Server in linked mode, perform this procedure on the vCenter Server that is used to install the plug-in initially, then restart the vCenter Server services on the linked vCenter Server.

In a web browser, navigate to http://vCenter_Server_name_or_IP/mob.

Where vCenter_Server_name_or_IP/mob is the name of your vCenter Server or its IP address.

Click Content.
Click ExtensionManager.
Select and copy the name of the plug-in you want to remove from the list of values under Properties. For a list of default plug-ins, see the Additional Information section of this article.
Click UnregisterExtension. A new window appears.
Paste the name of the plug-in and click Invoke Method. This removes the plug-in.
Close the window.
Refresh the Managed Object Type:ManagedObjectReference:ExtensionManager window to verify that the plug-in is removed successfully.

Note: If the plug-in still appears, you may have to restart the vSphere Client.
Note: You may have to enable the Managed Object Browser(mob) temporarily if previously disabled.'
  impact 0.5
  ref 'DPMS Target vCenter Server 6.0'
  tag check_id: 'C-64763r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64011'
  tag rid: 'SV-78501r1_rule'
  tag stig_id: 'VCWN-06-000035'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-69941r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
