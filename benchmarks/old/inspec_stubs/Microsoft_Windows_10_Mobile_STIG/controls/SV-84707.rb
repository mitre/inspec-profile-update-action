control 'SV-84707' do
  title 'Windows 10 Mobile must be configured to implement the management setting: Disable the ability for a device to send out advertisements/Bluetooth beacons to a Bluetooth peripheral.'
  desc 'Bluetooth usage could provide an attack vector for a hacker to connect to a mobile OS device without the knowledge of the user. Disabling Bluetooth advertising/beaconing reduces the risk of a non-authorized Bluetooth device connecting the DoD mobile OS device.

SFR ID: FMT_SMF_EXT.1.1 #20d'
  desc 'check', 'Review Windows 10 Mobile configuration settings to determine if the mobile device is enforcing the policy to prevent Bluetooth Low Energy (LE) apps from doing any Bluetooth advertising. 

This validation procedure is performed only on the MDM administration console. 

Check whether the appropriate setting is configured on the MDM.

Administration Console:

1. Ask the MDM administrator to show the Bluetooth device advertising" security policy.
2. Verify the "allow Bluetooth device advertising" security policy was set to disallowed for Windows 10 Mobile devices.

If the MDM does not disable the policy for "allow Bluetooth device advertising", this is a finding.'
  desc 'fix', 'Configure the MDM system to enforce a policy that restricts "allow Bluetooth device advertising" policy to prevent low energy Bluetooth devices from advertising. 

Deploy the policy on managed devices.'
  impact 0.5
  ref 'DPMS Target Windows 10 Mobile'
  tag check_id: 'C-70561r1_chk'
  tag severity: 'medium'
  tag gid: 'V-70085'
  tag rid: 'SV-84707r1_rule'
  tag stig_id: 'MSWM-10-200512'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-76321r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
