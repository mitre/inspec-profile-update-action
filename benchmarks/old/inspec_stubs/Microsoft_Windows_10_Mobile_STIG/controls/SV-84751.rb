control 'SV-84751' do
  title 'Windows 10 Mobile must be configured to implement the management setting: Disable the capability to use NFC.'
  desc 'NFC is a wireless technology that transmits small amounts of information from the device to the NFC reader. The data-in-transit (DIT) is not encrypted using FIPS 140-2 validated encryption. Any data transmitted can be potentially compromised. Disabling this feature mitigates this risk.

SFR ID: FMT_MOF.1.2 #4'
  desc 'check', 'Review Windows 10 Mobile configuration settings to determine if the mobile device is enforcing the policy to prevent the use of NFC for device to device communications. If feasible, use a spare device to test if NFC is disabled.

This validation procedure is performed on both the MDM administration console and the Windows 10 Mobile device. 

Check whether the appropriate setting is configured on the MDM.

Administration Console:

Ask the MDM administrator to verify the "allow NFC" security policy was set to be disallowed for Windows 10 Mobile devices.

On the Windows 10 Mobile device:

1. Go to "settings".
2. Navigate to "Devices", then tap on "NFC".
3. Verify that the "Tap to share" toggle is set to "Off" and cannot be changed.

If the MDM does not disable the policy for setting for "allow NFC" or if on the phone the "Tap to share" toggle is not set to "off" and can be changed on the "NFC" screen of the Settings app, this is a finding.'
  desc 'fix', 'Configure the MDM system to enforce a policy that restricts the "allow NFC" policy. 

Deploy the policy on managed devices.'
  impact 0.3
  ref 'DPMS Target Windows 10 Mobile'
  tag check_id: 'C-70605r1_chk'
  tag severity: 'low'
  tag gid: 'V-70129'
  tag rid: 'SV-84751r1_rule'
  tag stig_id: 'MSWM-10-910703'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-76365r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
