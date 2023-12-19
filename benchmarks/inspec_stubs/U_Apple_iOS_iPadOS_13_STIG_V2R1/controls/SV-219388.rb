control 'SV-219388' do
  title 'Apple iOS/iPadOS must implement the management setting: disable paired Apple Watch.'
  desc 'The STIG requires AO approval before an Apple Watch (DoD owned or personally owned) can be paired with a DoD owned iPhone to insure the AO has evaluated the risk in having sensitive DoD data transferred to and stored on an Apple Watch in their operational environment.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Determine if the site AO has approved the use of Apple Watch with DoD owned iPhones. Look for a document showing approval. Review configuration settings to confirm "Allow Paired Watch" is disabled, if not approved. If approved, this requirement is not applicable.

This a Supervised-only control. If the iPhone or iPad being reviewed is not Supervised by the MDM, this control is automatically a finding (if the AO has not approved the use of AirDrop for unmanaged data transfer).

If the iPhone or iPad being reviewed is Supervised by the MDM, follow these procedures:

This check procedure is performed on both the device management tool and the iPhone.

Note: If an organization has multiple configuration profiles, then the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

In the iOS management tool, verify "Allow Paired Watch" is unchecked.

On the iPhone:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles" or "Profiles & Device Management" or "Device Management". 
4. Tap the Configuration Profile from the iOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Paired Apple Watch not allowed" is listed.

If the AO has not approved pairing an Apple Watch with a DoD owned iPhone and "Paired Apple Watch not allowed" is not listed in both the management tool and on the Apple device, this is a finding.'
  desc 'fix', 'If the AO has not approved the use of Apple Watch with DoD owned iPhones, install a configuration profile to disable the Apple Watch control in the management tool. This a Supervised-only control.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 13'
  tag check_id: 'C-21113r547675_chk'
  tag severity: 'medium'
  tag gid: 'V-219388'
  tag rid: 'SV-219388r604137_rule'
  tag stig_id: 'AIOS-13-013100'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-21112r547676_fix'
  tag 'documentable'
  tag legacy: ['SV-106609', 'V-97505']
  tag cci: ['CCI-000366', 'CCI-000370', 'CCI-000097']
  tag nist: ['CM-6 b', 'CM-6 (1)', 'AC-20 (2)']
end
