control 'SV-242558' do
  title 'The Zebra Android 10 Work Profile must be configured to enforce the system application disable list.'
  desc "The system application disable list controls user access to/execution of all core and preinstalled applications. 
 
Core application: Any application integrated into Zebra Android 10 by Zebra. 
 
Preinstalled application: Additional noncore applications included in the Zebra Android 10 build by Zebra or the wireless carrier. 
 
Some system applications can compromise DoD data or upload users' information to non-DoD-approved servers. A user must be blocked from using such applications that exhibit behavior that can result in compromise of DoD data or DoD user information. 
 
The site administrator must analyze all preinstalled applications on the device and disable all applications not approved for DoD use by configuring the system application disable list.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review the Zebra Android 10 Work Profile configuration settings to confirm the system application disable list is enforced. This setting is enforced by default. 
 
This procedure is performed on the MDM Administrator console. 
 
Review the system app whitelist and verify that only approved apps are on the list.

If on the MDM console the system app whitelist contains unapproved core apps, this is a finding.'
  desc 'fix', 'Configure the Zebra Android 10 Work Profile to enforce the system application disable list. 

The required configuration is the default configuration when the device is enrolled. If the device configuration is changed, use the following procedure to bring the device back into compliance:

On the MDM, configure a list of approved Zebra core and preinstalled apps in the core app whitelist.'
  impact 0.5
  ref 'DPMS Target Zebra Android 10 COPE'
  tag check_id: 'C-45833r714517_chk'
  tag severity: 'medium'
  tag gid: 'V-242558'
  tag rid: 'SV-242558r714519_rule'
  tag stig_id: 'ZEBR-10-009400'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-45790r714518_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
