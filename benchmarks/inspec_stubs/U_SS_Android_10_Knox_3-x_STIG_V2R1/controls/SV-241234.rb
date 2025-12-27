control 'SV-241234' do
  title 'Samsung Android must be configured to require the user to present the Password Authentication Factor prior to decryption of protected data, encrypted DEKs, KEKs, and [selection: long-term trusted channel key material, all software-based key storage, no other keys] at startup.'
  desc 'The intent of this requirement is to prevent decryption of protected data before the user has authorized to the device using the Password Authentication Factor. The Password Authentication Factor is also required in order to derive the key used to decrypt sensitive data, which includes software-based secure key storage.

For devices with Full Disk Encryption (FDE) this is implemented by the Secure Startup feature. For devices with File Based Encryption (FBE) this is implemented by the Strong Protection feature.

Secure startup/Strong Protection protects the Samsung Android device by requiring the user password to be entered before the device starts up. When enabled, the default cryptographic keys are replaced with keys derived from the user password.

This feature must be enabled for a Samsung Android device to be in the NIAP-certified CC Mode of operation.

SFR ID: FMT_SMF_EXT.1.1 #47,
FIA_UAU_EXT.1.1'
  desc 'check', 'Review Samsung Android device configuration settings to determine if the user is required to present the Password Authentication Factor prior to decryption of protected data, encrypted DEKs, KEKs, and [selection: long-term trusted channel key material, all software-based key storage, no other keys] at startup.

Confirm if Method #1 or #2 is used for the Samsung Android device and follow the appropriate procedure.

This procedure is performed on the Samsung Android device only.

This setting cannot be managed by the management tool Administrator and is a UBE requirement.

****

Method #1: For Samsung Android devices that implement FDE: enable "Secure Startup".

On the Samsung Android device, do the following:
1. Open Settings >> Biometrics and security >> Other security settings >> Secure Startup.
2. Verify that "Require password when device powers on" is already selected and that "Do not require" is not selected.

If on the Samsung Android device "Do not require" is selected, this is a finding.

****

Method #2: For Samsung Android devices that implement FBE: enable "Strong Protection".

On the Samsung Android device, do the following:
1. Open Settings >> Biometrics and security >> Other security settings.
2. Verify that "Strong Protection" is enabled.

If on the Samsung Android device "Strong Protection" is not enabled, this is a finding.'
  desc 'fix', 'Configure Samsung Android to require the user to present the Password Authentication Factor prior to decryption of protected data, encrypted DEKs, KEKs, and [selection: long-term trusted channel key material, all software-based key storage, no other keys] at startup.

Do one of the following:
- Method #1: For Samsung Android devices that implement FDE: enable "Secure Startup".
- Method #2: For Samsung Android devices that implement FBE: enable "Strong Protection".

****

Method #1: For Samsung Android devices that implement FDE: enable "Secure Startup".

On the Samsung Android device, do the following:
1. Open Settings >> Biometrics and security >> Other security settings.
2. Tap "Secure Startup".
3. Tap option "Require password when device powers on".
4. Tap "Apply".
5. Enter current password.

****

Method #2: For Samsung Android devices that implement FBE: enable "Strong Protection".

Strong Protection is enabled by default.

On the Samsung Android device, do the following:
1. Open Settings >> Biometrics and security >> Other security settings.
2. Tap "Strong Protection".
3. Tap to enable.
4. Enter current password.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 10 with Knox 3-x'
  tag check_id: 'C-44510r680341_chk'
  tag severity: 'medium'
  tag gid: 'V-241234'
  tag rid: 'SV-241234r680343_rule'
  tag stig_id: 'KNOX-10-012700'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-44469r680342_fix'
  tag 'documentable'
  tag legacy: ['SV-109101', 'V-99997']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
