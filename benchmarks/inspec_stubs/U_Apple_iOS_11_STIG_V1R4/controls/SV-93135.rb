control 'SV-93135' do
  title 'Apple iOS must implement the management setting: not have any Family Members in Family Sharing.'
  desc "Apple's Family Sharing service allows Apple iOS users to create a Family Group whose members have several shared capabilities, including the ability to lock, wipe, play a sound on, or locate the Apple iOS devices of other members. Each member of the group must be invited to the group and accept that invitation. A DoD user's Apple iOS device may be inadvertently or maliciously wiped by another member of the Family Group. This poses a risk that the user could be without a mobile device for a period of time or lose sensitive information that has not been backed up to other storage media. Configuring Apple iOS devices so their associated Apple IDs are not members of Family Groups mitigates this risk.

Note: If the site uses Apple's optional Device Enrollment Program (DEP), this control is available as a supervised MDM control.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review configuration settings to confirm Family Sharing is disabled. Note that this is a User based Enforcement (UBE) control, which cannot be managed by an MDM server.

This check procedure is performed on the Apple iOS device.

On the Apple iOS device:
1. Open the Settings app.
2. Tap "iCloud".
3. If "Set Up Family Sharing..." is listed, the device is compliant.
4. If "Setup Family Sharing..." is not listed, tap "Family".
5. Verify no email addresses or names are listed under "FAMILY MEMBERS".

Note: The Apple iOS device must be connected to the Internet to conduct this validation procedure. Otherwise, the device will display the notice "Family information is not available", in which case it cannot be determined if the configuration is compliant.

If names or email addresses are listed under "FAMILY MEMBERS" on the Apple iOS device, this is a finding.

Note: If the site has implemented DEP (not required), this setting can be managed via the MDM (supervised mode).'
  desc 'fix', 'The user must either remove all members from the Family Group on the Apple iOS device or associate the device with an Apple ID that is not a member of a Family Group.'
  impact 0.3
  ref 'DPMS Target Apple iOS 11'
  tag check_id: 'C-77991r1_chk'
  tag severity: 'low'
  tag gid: 'V-78429'
  tag rid: 'SV-93135r1_rule'
  tag stig_id: 'AIOS-11-012200'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-85161r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
