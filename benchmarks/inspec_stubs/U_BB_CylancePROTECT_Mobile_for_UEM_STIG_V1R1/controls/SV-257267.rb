control 'SV-257267' do
  title 'CylancePROTECT Mobile must be configured with the following Android security patch compliance and hardware certificate attestation controls:
-"Android hardware attestation frequency" = 6 hours
-"Device grace period" = 0 hours
-"Challenge frequency for noncompliant devices" =  6 hours.'
  desc 'The required application configurations will ensure that the minimum security baseline of the system is maintained to limit exposure of sensitive data and unauthorized access to the mobile device.'
  desc 'check', 'Verify the following Android security patch compliance and hardware certificate attestation controls are enabled for CylancePROTECT Mobile:
-"Android hardware attestation frequency" = 6 hours.
-"Device grace period" = 0 hours.
-"Challenge frequency for noncompliant devices =  6 hours.

1. Log on to the BlackBerry UEM console.
2. In the management console, click Settings >> General Settings >> Attestation.
3. In the "Android hardware attestation frequency" section, select verify "Enable hardware patch level attestation challenges for Android devices" is selected.
4. In the "Challenge frequency" drop-down list, verify the device attestation response is set to "6 hours".
5. In the "Device grace period drop-down" list, verify the grace period is set to "0 hours" (no grace period).
6. In the "Challenge frequency for noncompliant devices" field, verify the frequency UEM tests the integrity of devices that are not currently in compliance is set to "6 hours".

If required Android security patch compliance and hardware certificate attestation controls are not enabled, this is a finding.'
  desc 'fix', 'Configure the following  Android security patch compliance and hardware certificate attestation controls:
-"Android hardware attestation frequency" = 6 hours.
-"Device grace period" = 0 hours.
-"Challenge frequency for noncompliant devices" =  6 hours.

1. Log on to the BlackBerry UEM console.
2. In the management console, click Settings >> General Settings >> Attestation.
3. In the "Android hardware attestation frequency" section, select "Enable hardware patch level attestation challenges for Android devices" checkbox.
4. in the "Challenge frequency" drop-down list, set the device must return an attestation response to "6 hours".
5. In the Device grace period drop-down list, set the grace period to "0 hours" (no grace period).
6. In the Challenge frequency for noncompliant devices field, set  how often UEM tests the integrity of devices that are not currently in compliance to "6 hours".
7. Click "Save".'
  impact 0.5
  ref 'DPMS Target BlackBerry CylancePROTECT Mobile for UEM'
  tag check_id: 'C-60951r918383_chk'
  tag severity: 'medium'
  tag gid: 'V-257267'
  tag rid: 'SV-257267r918385_rule'
  tag stig_id: 'BBCP-00-013300'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-60893r918384_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
