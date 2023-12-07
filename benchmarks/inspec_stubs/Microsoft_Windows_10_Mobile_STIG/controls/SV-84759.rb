control 'SV-84759' do
  title 'Windows 10 Mobile must be configured to implement the management setting: Disable the capability for a user to manually unenroll from MDM management.'
  desc 'The use of an MDM allows an organization to assign values to security-related parameters across all the devices it manages. This provides assurance that the required mobile OS security controls are being enforced and that the device user or an adversary has not modified or disabled the controls. If a user has the ability on their device to manually unenroll from MDM management, this removes all IA controls and exposes the device and the user to a number of threat vectors and takes them out of compliance.
Disabling this feature mitigates the risk from loss of control and ensures that the devices maintain the required locked down state.

SFR ID: FMT_SMF_EXT.1.1 #45'
  desc 'check', %q(Review Windows 10 Mobile configuration settings to determine if the mobile device is restricted from unenrolling itself from MDM management. If feasible, use a spare device to determine if bringing up the enrollment app it is possible to unenroll that device.

This validation procedure is performed on both the MDM administration console and the Windows 10 Mobile device.

On the MDM administration console:

1. Ask the MDM administrator to verify the phone compliance policy.
2. Find the setting for "allow manual unenrollment from management".
3. Verify that setting restriction is turned off/disallowed.

On the Windows 10 Mobile device:

1. Go to "settings".
2. Navigate to "Accounts", then tap on "Work access".
3. Scroll down the screen and look for a section titled "Enroll in to device management" to see if there is a company/agency name with the small text of "connected" under it.
4. Tap on that enrollment name, which should take you to a new page with details about the enrollment and have a "refresh" and "wastebasket (delete)" icon at the bottom.
5. Tap on the "wastebasket (delete)" icon to unenroll from MDM management. A message box should come up with a "Can't delete account - Your company policy prevents you from deleting your workplace account" alert.

If the MDM does not disable the policy for setting for "allow manual unenrollment from management" or if on the phone a message starting with the sentence "Can't delete account - Your company policy prevents you from deleting your workplace account" is not shown when tapping on the wastebasket icon in the Work Access app, this is a finding.)
  desc 'fix', 'Configure the MDM system with a security policy that requires the "allow manual unenrollment from management" capability be disabled for Windows 10 Mobile devices. 

Deploy the MDM policy to managed devices.'
  impact 0.5
  ref 'DPMS Target Windows 10 Mobile'
  tag check_id: 'C-70613r1_chk'
  tag severity: 'medium'
  tag gid: 'V-70137'
  tag rid: 'SV-84759r1_rule'
  tag stig_id: 'MSWM-10-911104'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-76373r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
