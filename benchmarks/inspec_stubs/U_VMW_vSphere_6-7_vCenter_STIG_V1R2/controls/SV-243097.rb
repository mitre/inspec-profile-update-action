control 'SV-243097' do
  title 'vCenter Server plugins must be verified.'
  desc 'The vCenter Server includes a vSphere Client extensibility framework, which provides the ability to extend the vSphere Client with menu selections or toolbar icons that provide access to vCenter Server add-on components or external, web-based functionality. 

vSphere Client plugins or extensions run at the same privilege level as the user. Malicious extensions might masquerade as useful add-ons while compromising the system by stealing credentials or incorrectly configuring the system.'
  desc 'check', 'Verify the vSphere Client used by administrators includes only authorized extensions from trusted sources.

From the vSphere Client, go to Administration >> Solutions >> Client Plug-Ins. 

View the Installed/Available Plug-ins list and verify they are all identified as authorized VMware, third-party (partner), and/or site-specific approved plug-ins.

If any Installed/Available plug-ins in the viewable list cannot be verified as an allowed vSphere Client plug-ins from trusted sources, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Administration >> Solutions >> Client Plug-Ins.

Click the radio button next to the unknown plug-in and click disable. Proceed to uninstall the plug-in.

To remove plug-ins:

If vCenter Server is in linked mode, perform this procedure on the vCenter Server that is used to install the plug-in initially and then restart the vCenter Server services on the linked vCenter Server.

In a web browser, navigate to http://vCenter_Server_name_or_IP/mob.

vCenter_Server_name_or_IP/mob is the name of the vCenter Server or its IP address.

Click "Content".

Click "ExtensionManager".

Select and copy the name of the plug-in to be removed from the list of values under "Properties". 

Click "UnregisterExtension". A new window appears.

Paste the name of the plug-in and click "Invoke Method". This removes the plug-in.

Close the window.

Refresh the "Managed Object Type:ManagedObjectReference:ExtensionManager" window to verify that the plug-in is removed successfully.

Note: If the plug-in still appears, restart the vSphere Client.

Note: Enable the Managed Object Browser (MOB) temporarily if it was previously disabled.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46372r719532_chk'
  tag severity: 'medium'
  tag gid: 'V-243097'
  tag rid: 'SV-243097r719534_rule'
  tag stig_id: 'VCTR-67-000035'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-46329r719533_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
