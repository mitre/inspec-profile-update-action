control 'SV-94977' do
  title 'The Samsung Android 8 with Knox CONTAINER must implement the management setting: Configure CONTAINER application disable list.'
  desc "Applications from various sources (including the vendor, the carrier, and Google) are installed on the device at the time of manufacture. Core apps are apps pre-installed by Google. Third-party pre-installed apps include apps from the vendor and carrier. 

Some of the applications can compromise DoD data or upload users' information to non-DoD-approved servers. A user must be blocked from using such applications that exhibit behavior that can result in compromise of DoD data or DoD user information. The site Administrator must analyze all pre-installed applications on the device and block all applications not approved for DoD use by configuring the application disable list.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if the mobile device is enforcing CONTAINER application disable list.

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Application disable list" setting in the "Android Knox CONTAINER >> CONTAINER Application" rule. 
2. Verify the list contains all core and pre-installed applications not approved for DoD use by the Authorizing Official (AO).

Note: Refer to the Supplemental document for additional information.

On the Samsung Android 8 with Knox device, do the following:
1. Open the Knox CONTAINER.
2. Attempt to launch an application that is included on the disable list. 

Note: This application should not be visible.

If the MDM console "Application disable list" is not set to contain all core and pre-installed applications not approved by DoD or on the Samsung Android 8 with Knox device, the user is able to successfully launch an application on this list, this is a finding.'
  desc 'fix', 'Configure Samsung Android 8 with Knox to enforce CONTAINER application disabled list.

On the MDM console, add all pre-installed CONTAINER applications that are not DoD-approved to the "Application disable list" setting in the "Android Knox CONTAINER >> CONTAINER Application" rule.

Note: Refer to the Supplemental document for additional information.

Note: Include Samsung Accounts on the list.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-79945r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80273'
  tag rid: 'SV-94977r1_rule'
  tag stig_id: 'KNOX-08-000800'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-87079r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
