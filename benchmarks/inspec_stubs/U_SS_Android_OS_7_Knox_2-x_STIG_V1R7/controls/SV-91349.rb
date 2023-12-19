control 'SV-91349' do
  title 'The Samsung Android 7 with Knox must implement the management setting: Configure Container application disable list.'
  desc "Applications from various sources (including the vendor, the carrier, and Google) are installed on the device at the time of manufacture. Core apps are apps preinstalled by Google. Third-party preinstalled apps included apps from the vendor and carrier. Some of the applications can compromise DoD data or upload users' information to non-DoD-approved servers. A user must be blocked from using such applications that exhibit behavior that can result in compromise of DoD data or DoD user information. The site administrator must analyze all pre-installed applications on the device and block all applications not approved for DoD use by configuring the application disable list.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Not Applicable for the COBO use case.

Review Samsung Android 7 with Knox configuration settings to determine if the mobile device is enforcing Container application disabled list.

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 7 with Knox device.

On the MDM console, do the following:
1. Ask the MDM administrator to display the "Application disable list" setting in the "Android Knox Container >> Container Application" rule. 
2. Verify the list contains all core and pre-installed applications not approved for DoD use by the Authorizing Official (AO).

Note: Refer to the Supplemental document for additional information.

On the Samsung Android 7 with Knox device, do the following:
1. Open the Knox container.
2. Attempt to launch an application that is included on the disable list. 

Note: This application should not be visible.

If the MDM console "Application disable list" is not set to contain all core and pre-installed applications not approved by DoD or on the Samsung Android 7 with Knox device, the user is able to successfully launch an application on this list, this is a finding.'
  desc 'fix', 'Configure the Samsung Android 7 with Knox to enforce Container application disabled list.

On the MDM console, add all pre-installed container applications that are not DoD-approved to the "Application disable list" setting in the "Android Knox Container >> Container Application" rule. 

Note: Refer to the Supplemental document for additional information.

Note: Include Samsung Accounts on the list.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76323r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76653'
  tag rid: 'SV-91349r1_rule'
  tag stig_id: 'KNOX-07-914100'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-83347r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
