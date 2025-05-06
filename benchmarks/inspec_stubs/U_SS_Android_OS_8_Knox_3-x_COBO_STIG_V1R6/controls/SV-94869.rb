control 'SV-94869' do
  title 'Samsung Android 8 with Knox must implement the management setting: Configure application disable list.'
  desc "Applications from various sources (including the vendor, the carrier, and Google) are installed on the device at the time of manufacture. Core apps are apps pre-installed by Google. Third-party pre-installed apps include apps from the vendor and carrier.

Some of the applications can compromise DoD data or upload users' information to non-DoD-approved servers. A user must be blocked from using such applications that exhibit behavior that can result in compromise of DoD data or DoD user information. The site Administrator must analyze all pre-installed applications on the device and block all applications not approved for DoD use by configuring the application disable list.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review Samsung Android 8 with Knox CONTAINER configuration settings to determine if the mobile device is enforcing application disable list.

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Application disable list" setting in the "Android Applications" rule. 
2. Verify the list contains all core and pre-installed applications not approved for DoD use by the Authorizing Official (AO).

Note: Refer to the Supplemental document for additional information.

On the Samsung Android 8 with Knox device, attempt to launch an application that is included on the disable list. 

Note: This application should not be visible.

If the MDM console "Application disable list" is not set to contain all core and pre-installed applications not approved by DoD or on the Samsung Android 8 with Knox device, the user is able to successfully launch an application on this list, this is a finding.'
  desc 'fix', 'Configure Samsung Android 8 with Knox to enforce application disable list.

On the MDM console, add all pre-installed applications that are not DoD-approved to the "Application disable list" setting in the "Android Applications" rule.

Note: Refer to the Supplemental document for additional information.

Note: Include Samsung Accounts on the list.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COBO use case'
  tag check_id: 'C-79833r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80165'
  tag rid: 'SV-94869r1_rule'
  tag stig_id: 'KNOX-08-000700'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-86971r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
