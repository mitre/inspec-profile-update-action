control 'SV-250745' do
  title 'vSphere Client plugins must be verified.'
  desc 'The vCenter Server includes a vSphere Client extensibility framework, which provides the ability to extend the vSphere Client with menu selections or toolbar icons that provide access to vCenter Server add-on components or external, Web-based functionality. vSphere Client plugins or extensions run at the same privilege level as the user. Malicious extensions might masquerade as useful add-ons while compromising the system by stealing credentials or incorrectly configuring the system.'
  desc 'check', 'Verify the vSphere Client used by administrators includes only authorized extensions from trusted sources:
From the vSphere Client, "Plug-ins>> Manage Plug-ins" and click the Installed Plug-ins tab. View the Installed/Available Plug-ins list and verify they are all identified as authorized VMware, 3rd party (Partner) and/or site-specific (locally developed and site) approved plug-ins.

If any Installed/Available plug-ins in the viewable list cannot be verified as vSphere Client plug-ins and/or authorized extensions from trusted sources, this is a finding.'
  desc 'fix', 'Disable/remove all listed plug-ins that cannot be verified as distributed from trusted sources:
From the vSphere client, connect to the vCenter server.
On the menu bar, go to "Plug-ins >> Manage Plug-ins".
Under Installed Plug-ins, right-click the plug-in of choice and select Disable.'
  impact 0.5
  ref 'DPMS Target VMware vCenter Server Version 5'
  tag check_id: 'C-54180r799923_chk'
  tag severity: 'medium'
  tag gid: 'V-250745'
  tag rid: 'SV-250745r799925_rule'
  tag stig_id: 'VCENTER-000029'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-54134r799924_fix'
  tag 'documentable'
  tag legacy: ['V-39564', 'SV-51422']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
