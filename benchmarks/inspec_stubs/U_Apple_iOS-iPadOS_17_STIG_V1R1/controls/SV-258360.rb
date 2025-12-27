control 'SV-258360' do
  title 'Apple iOS/iPadOS 17 must implement the management setting: disable paired Apple Watch.'
  desc 'Authorizing official (AO) approval is required before an Apple Watch (DOD owned or personally owned) can be paired with a DOD-owned iPhone to ensure the AO has evaluated the risk in having sensitive DOD data transferred to and stored on an Apple Watch in their operational environment.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Determine if the site AO has approved the use of Apple Watch with DOD-owned iPhones. Look for a document showing approval. If not approved, review configuration settings to confirm "Allow Paired Watch" is disabled. If approved, this requirement is not applicable.

This a supervised-only control. If the iPhone or iPad being reviewed is not supervised by the MDM, this control is automatically a finding (if the AO has not approved the use of Apple Watch for unmanaged data transfer).

If the iPhone or iPad being reviewed is supervised by the MDM, follow these procedures:

This check procedure is performed on both the device management tool and the iPhone.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

In the iOS management tool, verify "Allow Paired Watch" is unchecked.

On the iPhone:
1. Open the Settings app.
2. Tap "General".
3. Tap "VPN & Device Management". 
4. Tap the Configuration Profile from the iOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Paired Apple Watch not allowed" is listed.

If the AO has not approved pairing an Apple Watch with a DOD-owned iPhone and "Paired Apple Watch not allowed" is not listed both in the management tool and on the Apple device, this is a finding.'
  desc 'fix', 'If the AO has not approved the use of Apple Watch with DOD-owned iPhones, install a configuration profile to disable the Apple Watch control in the management tool. This a supervised-only control.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 17 STIG'
  tag check_id: 'C-62101r927761_chk'
  tag severity: 'medium'
  tag gid: 'V-258360'
  tag rid: 'SV-258360r927763_rule'
  tag stig_id: 'AIOS-17-012600'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62025r927762_fix'
  tag 'documentable'
  tag cci: ['CCI-000097', 'CCI-000366']
  tag nist: ['AC-20 (2)', 'CM-6 b']
end
