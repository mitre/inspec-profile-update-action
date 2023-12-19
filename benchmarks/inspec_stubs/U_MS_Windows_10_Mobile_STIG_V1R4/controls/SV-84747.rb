control 'SV-84747' do
  title 'Windows 10 Mobile must be configured to implement the management setting: Disable the device Bluetooth Discoverable Mode.'
  desc 'Bluetooth usage could provide an attack vector for a hacker to connect to a mobile OS device without the knowledge of the user. Disabling Discoverable mode reduces the risk of a non-authorized Bluetooth device connecting the DoD mobile OS device.

SFR ID: FMT_SMF_EXT.1.1 #20a'
  desc 'check', 'Review MDM configuration settings to determine if the required Bluetooth discoverability mode is being disabled. 

This validation procedure is performed only on the MDM administration console. 

On the MDM administration console:

Ask the MDM administrator to verify the "allow Bluetooth device to be discoverable" security policy was set to be disallowed for Windows 10 Mobile devices.

If the MDM is not configured to restrict the "allow Bluetooth device to be discoverable", this is a finding.'
  desc 'fix', 'Configure the MDM system with a security policy that restricts the "allow Bluetooth device to be discoverable" capability to be disabled for Windows 10 Mobile devices. 

Deploy the MDM policy to managed devices.'
  impact 0.5
  ref 'DPMS Target Windows 10 Mobile'
  tag check_id: 'C-70601r1_chk'
  tag severity: 'medium'
  tag gid: 'V-70125'
  tag rid: 'SV-84747r1_rule'
  tag stig_id: 'MSWM-10-910502'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-76361r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
