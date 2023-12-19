control 'SV-94947' do
  title 'Samsung Android 8 with Knox must be configured to: Disable upload of DoD contact information.'
  desc "Caller ID and spam protection apps let a user know who is calling even when the number is not on the user's contact list by using an online service to do the lookup. Users can also upload their and their contacts' names and numbers into an online service.

This could allow potentially DoD sensitive data, such as names and telephone numbers, to be compromised.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'If the feature is not present as described on a specific device model, this requirement is Not Applicable (NA).

Review documentation on the Samsung Android 8 with Knox and inspect the configuration on the Samsung Android 8 with Knox to disable upload of DoD contact information.

This validation procedure is performed on the Samsung Android 8 with Knox device only.

On the Samsung Android 8 with Knox device, do the following:
1. Open the "Phone" app.
2. Open the "Settings" via the overflow menu.
3. Open "Caller ID and spam protection".
4. Verify that "Share name and phone number" is "Off".
5. Open the device settings.
6. Select "Apps".
7. Verify no smart call and caller ID applications in the list are set to upload contact information.

If the Samsung Android 8 with Knox device "Share name and phone number" is not set to "Off" or an application is set to upload contact information, this is a finding.

Note: This setting cannot be managed by the MDM Administrator and is a User Based Enforcement (UBE) requirement.'
  desc 'fix', 'If the feature is not present as described on a specific device model, this requirement is Not Applicable (NA).

Configure Samsung Android 8 with Knox to disable upload of DoD contact information.

On the Samsung Android 8 with Knox device, do the following:
1. Open the "Phone" app.
2. Open the "Settings" via the overflow menu.
3. Open "Caller ID and spam protection".
4. Verify that "Share name and phone number" is "Off".
5. Open the device settings.
6. Select "Apps".
7. Verify no smart call and caller ID applications in the list are set to upload contact information.

Note: On the Samsung Android 8 with Knox device, Smart Call is disabled by default.'
  impact 0.3
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COBO use case'
  tag check_id: 'C-79915r1_chk'
  tag severity: 'low'
  tag gid: 'V-80243'
  tag rid: 'SV-94947r1_rule'
  tag stig_id: 'KNOX-08-016500'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-87049r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
