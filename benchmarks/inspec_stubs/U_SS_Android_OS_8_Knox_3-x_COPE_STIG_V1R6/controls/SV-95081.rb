control 'SV-95081' do
  title 'The Samsung Android 8 with Knox CONTAINER must be configured to: Disable upload of DoD contact information.'
  desc "Caller ID and spam protection apps let a user know who is calling even when the number is not on the user's contact list by using an online service to do the lookup. Users can also upload their and their contacts' names and numbers into an online service.

This could allow potentially DoD sensitive data, such as names and telephone numbers, to be compromised.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'If the feature is not present as described on a specific device model, this requirement is Not Applicable (NA).

Review documentation on the Samsung Android 8 with Knox CONTAINER and inspect the configuration on the Samsung Android 8 with Knox CONTAINER to disable upload of DoD contact information.

This validation procedure is performed on the Samsung Android 8 with Knox device CONTAINER only.

On the Samsung Android 8 with Knox device CONTAINER, do the following:
1. Open the CONTAINER settings.
2. Select "Apps".
3. Verify no Smart Call and caller ID applications in the list are set to upload contact information.

If on the Samsung Android 8 with Knox device CONTAINER, a smart call or caller ID application is set to upload DoD contact information, this is a finding. 

Note: This setting cannot be managed by the MDM Administrator and is a User Based Enforcement (UBE) requirement.'
  desc 'fix', 'If the feature is not present as described on a specific device model, this requirement is Not Applicable (NA).

Configure the Samsung Android 8 with Knox CONTAINER to disable upload of DoD contact information.

On the Samsung Android 8 with Knox device CONTAINER, do the following:
1. Open the CONTAINER settings.
2. Select "Apps".
3. Verify no Smart Call and caller ID applications in the list are set to upload contact information.'
  impact 0.3
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-80049r1_chk'
  tag severity: 'low'
  tag gid: 'V-80377'
  tag rid: 'SV-95081r1_rule'
  tag stig_id: 'KNOX-08-016600'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-87183r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
