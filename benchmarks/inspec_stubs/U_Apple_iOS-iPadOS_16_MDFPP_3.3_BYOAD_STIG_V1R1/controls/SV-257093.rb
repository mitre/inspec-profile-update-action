control 'SV-257093' do
  title 'The iOS/iPadOS 16 BYOAD must be configured so that managed data and apps are removed if the device is no longer receiving security or software updates.'
  desc 'When a BYOAD is out of compliance, DOD data and apps must be removed to protect against compromise of sensitive DOD information.

Reference: DOD policy "Use of Non-Government Mobile Devices". 3.b.(1)ii.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify the EMM system is configured to wipe managed data and apps if the iOS/iPadOS 16 BYOAD is no longer receiving security or software updates. 

When managed data and apps are wiped, all managed data and files in the Files app must be wiped as well. The exact procedure will depend on the EMM system used at the site.

If the EMM system is not configured to wipe managed data and apps if the iOS/iPadOS 16 BYOAD is no longer receiving security or software updates, this is a finding.'
  desc 'fix', 'Configure the EMM system so managed data and apps are removed if the iOS/iPadOS 16 BYOAD is no longer receiving security or software updates. 

Note: When managed data and apps are wiped, all managed data and files in the Files app must be wiped as well. The exact procedure will depend on the EMM system used at the site.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 16 MDFPP 3.3 BYOAD'
  tag check_id: 'C-60778r904022_chk'
  tag severity: 'medium'
  tag gid: 'V-257093'
  tag rid: 'SV-257093r904024_rule'
  tag stig_id: 'AIOS-16-800100'
  tag gtitle: 'PP-BYO-000100'
  tag fix_id: 'F-60719r904023_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
