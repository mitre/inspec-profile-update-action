control 'SV-217740' do
  title 'Samsung Android must be configured to enforce that Strong Protection is enabled. This requirement is Not Applicable (NA) for devices older than Galaxy S10.'
  desc "Strong Protection protects the Samsung Android devices that use File Based Encryption (FBE). When Strong Protection is enabled, the default cryptographic keys used to protect the user's apps and data are replaced with keys derived from the user password.

This feature must be enabled for a Samsung Android device to be in the NIAP-certified CC mode of operation.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review device configuration settings to confirm that Strong Protection is enabled.

This procedure is performed on the Samsung Android Galaxy S10 (or newer) devices only.

This setting cannot be managed by the MDM administrator and is a User-Based Enforcement (UBE) requirement.

On the Samsung Android device, do the following:
1. Open Settings.
2. Tap "Biometric and security".
3. Tap "Other security settings".
4. Verify "Strong Protection" is enabled.

If on the Samsung Android device, "Strong Protection” is disabled, this is a finding.'
  desc 'fix', 'Configure Samsung Android to enable Strong Protection.

This guidance is only applicable to Galaxy S10 (or newer) devices.

On the Samsung Android device, do the following:
1. Open Settings.
2. Tap "Biometrics and security".
3. Tap "Other security settings".
4. Tap "Strong Protection".
5. Tap to enable.
6. Enter the current password.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 9 Knox 3-x COBO KPE Legacy'
  tag check_id: 'C-18958r362368_chk'
  tag severity: 'medium'
  tag gid: 'V-217740'
  tag rid: 'SV-217740r388482_rule'
  tag stig_id: 'KNOX-09-001485'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-18956r362369_fix'
  tag 'documentable'
  tag legacy: ['SV-103727', 'V-93641']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
