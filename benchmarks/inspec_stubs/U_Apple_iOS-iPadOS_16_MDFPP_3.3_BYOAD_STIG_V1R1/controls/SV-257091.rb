control 'SV-257091' do
  title 'The iOS/iPadOS 16 BYOAD must be configured to either disable access to DOD data, IT systems, and user accounts or wipe managed data and apps if the EMM system detects native security controls are disabled.'
  desc 'Examples of indicators that the native device security controls have been disabled include jailbroken or rooted devices.

When a BYOAD is out of compliance, DOD data and apps must be removed to protect against compromise of sensitive DOD information.

Note: The site should review DOD and local data retention policies before wiping the work profile of a BYOAD device.

Reference: DOD policy "Use of Non-Government Mobile Devices". 3.b.(4), 3.b.(5)i.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify the EMM has been configured to either disable access to DOD data, IT systems, and user accounts on the iOS/iPadOS 16 BYOAD or wipe managed data and apps if it has been detected that native BYOAD security controls are disabled (e.g., jailbroken/rooted). 

When managed data and apps are wiped, all managed data and files in the Files app must be wiped as well. The exact procedure will depend on the EMM system used at the site.

If the EMM has not been configured to either disable access to DOD data, IT systems, and user accounts on the iOS/iPadOS 16 BYOAD or wipe managed data and apps if it has been detected that native BYOAD security controls are disabled, this is a finding.'
  desc 'fix', 'Configure the EMM to either disable access to DOD data, IT systems, and user accounts on the iOS/iPadOS 16 BYOAD or wipe managed data and apps if it has been detected that native iOS/iPadOS 16 BYOAD security controls are disabled (e.g., jailbroken/rooted). The exact procedure will depend on the EMM system used at the site. 

Note: When managed data and apps are wiped, all managed data and files in the Files app must be wiped as well.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 16 MDFPP 3.3 BYOAD'
  tag check_id: 'C-60776r904016_chk'
  tag severity: 'medium'
  tag gid: 'V-257091'
  tag rid: 'SV-257091r904018_rule'
  tag stig_id: 'AIOS-16-800080'
  tag gtitle: 'PP-BYO-000080'
  tag fix_id: 'F-60717r904017_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
