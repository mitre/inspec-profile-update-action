control 'SV-258351' do
  title 'Apple iOS/iPadOS 17 must implement the management setting: not have any Family Members in Family Sharing.'
  desc "Apple's Family Sharing service allows Apple iOS/iPadOS users to create a Family Group whose members have several shared capabilities, including the ability to lock, wipe, play a sound on, or locate the iPhone and iPads of other members. Each member of the group must be invited to the group and accept that invitation. A DOD user's iPhone and iPad may be inadvertently or maliciously wiped by another member of the Family Group. This poses a risk that the user could be without a mobile device for a period of time or lose sensitive information that has not been backed up to other storage media. Configuring iPhone and iPads so their associated Apple IDs are not members of Family Groups mitigates this risk.

Note: If the site uses Apple's optional Automatic Device Enrollment, this control is available as a supervised MDM control.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review configuration settings to confirm Family Sharing is disabled. Note that this is a User-Based Enforcement (UBE) control, which cannot be managed by an MDM server.

This check procedure is performed on the iPhone and iPad.

On the iPhone and iPad:
1. Open the Settings app.
2. At the top of the screen, if "Sign in to your iPhone" is listed, this requirement has been met.
3. If the user profile is signed into iCloud, tap the user name.
4. Tap "Family Sharing".
5. Verify no accounts are listed other than the "Organizer".

Note: The iPhone and iPad must be connected to the internet to conduct this validation procedure. Otherwise, the device will display the notice "Family information is not available", in which case configuration compliance cannot be determined.

If accounts (names or email addresses) are listed under "FAMILY MEMBERS" on the iPhone and iPad, this is a finding.'
  desc 'fix', 'The user must either remove all members from the Family Group on the iPhone and iPad or associate the device with an Apple ID that is not a member of a Family Group.'
  impact 0.3
  ref 'DPMS Target Apple iOS-iPadOS 17 STIG'
  tag check_id: 'C-62092r927734_chk'
  tag severity: 'low'
  tag gid: 'V-258351'
  tag rid: 'SV-258351r927736_rule'
  tag stig_id: 'AIOS-17-011600'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62016r927735_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002008']
  tag nist: ['CM-6 b', 'IA-5 (14)']
end
