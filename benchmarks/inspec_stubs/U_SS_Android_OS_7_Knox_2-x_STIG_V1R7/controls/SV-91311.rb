control 'SV-91311' do
  title 'The Samsung Android 7 with Knox must be configured to Disable Smart Call.'
  desc "Smart Call feature provides Caller ID and spam protection. It lets the user know who is calling even when the number is not on the user's contact list by using an online service to do the lookup. Users can also upload their name and number into the online service.

This could allow potentially DoD-sensitive data such as names and telephone number to be compromised.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review documentation on the Samsung Android 7 with Knox and inspect the configuration on the Samsung Android 7 with Knox to disable the Smart Call.

This validation procedure is performed on Samsung Android 7 with Knox device only.

On the Samsung Android 7 with Knox device, do the following:
1. Open the Phone app.
2. Open the Settings via the "3 dot menu".
3. Verify that "Caller ID and spam protection" is "Off".

If the Samsung Android 7 with Knox device, "Caller ID and spam protection" is not set to "Off", this is a finding.

Note: This setting cannot be managed by the MDM administrator and is a User Based Enforcement (UBE) requirement.'
  desc 'fix', 'Configure the Samsung Android 7 with Knox to disable Smart Call.

On the Samsung Android 7 with Knox device Smart Call is disabled by default.'
  impact 0.3
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76285r1_chk'
  tag severity: 'low'
  tag gid: 'V-76615'
  tag rid: 'SV-91311r1_rule'
  tag stig_id: 'KNOX-07-018000'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-83309r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
