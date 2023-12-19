control 'SV-91339' do
  title 'The Samsung Android 7 with Knox must implement the management setting: Configure to prohibit more than 10 consecutive failed Container authentication attempts.'
  desc 'Users must not be able to override the system policy on the maximum number of consecutive failed authentication attempts because this could allow them to raise the maximum, thus giving adversaries more chances to guess/brute force passwords, which increases the risk of the mobile device being compromised. Therefore, only administrators should have the authority to set consecutive failed authentication attempt policies.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Not Applicable for the COBO use case.

Review Samsung Android 7 with Knox configuration settings to determine if the mobile device is enforcing 10 or less failed Container authentication attempts. 

This validation procedure is performed on both the MDM Administration Console only.

On the MDM console, do the following:
1. Ask the MDM administrator to display the "Maximum Failed Attempts for wipe" field in the "Android Knox Container >> Container Password Restrictions" rule.
2. Verify the value of the setting is "10" or less.

If the MDM console "Maximum Failed Attempts for wipe" is not set to "10" or less or on the Samsung Android 7 with Knox device, the user is able to fail more than "10" authentication attempts, this is a finding.'
  desc 'fix', 'Configure the Samsung Android 7 with Knox to enforce "10" or less failed Container authentication attempts.

On the MDM console, set the "Maximum Failed Attempts for wipe" to the organization-defined value in the "Android Knox Container >> Container Password Restrictions" rule.'
  impact 0.3
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76313r1_chk'
  tag severity: 'low'
  tag gid: 'V-76643'
  tag rid: 'SV-91339r1_rule'
  tag stig_id: 'KNOX-07-913400'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-83337r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
