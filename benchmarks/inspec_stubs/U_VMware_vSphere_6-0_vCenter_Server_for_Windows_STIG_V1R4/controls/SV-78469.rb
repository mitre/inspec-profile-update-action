control 'SV-78469' do
  title 'The system must enable SSL for Network File Copy (NFC).'
  desc 'NFC is the mechanism used to migrate or clone a VM between two ESXi hosts over the network. By default, NFC over SSL is enabled (i.e., "True") within a vSphere cluster but the value of the setting is null. Clients check the value of the setting and default to not using SSL for performance reasons if the value is null. This behavior can be changed by ensuring the setting has been explicitly created and set to "True". This will force clients to use SSL. Without this setting VM contents could potentially be sniffed if the management network is not adequately isolated and secured.'
  desc 'check', 'From the vSphere Web Client go to vCenter Inventory Lists >> vCenter Servers >> Select your vCenter Server >> Manage >> Settings >> Advanced Settings.  Verify that config.nfc.useSSL is set to true.

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:

Get-AdvancedSetting -Entity <vcenter server name> -Name config.nfc.useSSL and verify it is set to true.

If the config.nfc.useSSL is set to a value other than true or does not exist, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to vCenter Inventory Lists >> vCenter Servers >> Select your vCenter Server >> Manage >> Settings >> Advanced Settings.  Click Edit and edit the config.nfc.useSSL setting to true or if the value does not exist create it by entering the values in the Key and Value fields and clicking Add.

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:

If the setting already exists:

Get-AdvancedSetting -Entity <vcenter server name> -Name config.nfc.useSSL | Set-AdvancedSetting -Value true

If the setting does not exist:

New-AdvancedSetting -Entity <vcenter server name> -Name config.nfc.useSSL -Value true'
  impact 0.5
  ref 'DPMS Target vCenter Server 6.0'
  tag check_id: 'C-64731r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63979'
  tag rid: 'SV-78469r1_rule'
  tag stig_id: 'VCWN-06-000021'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-69909r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
