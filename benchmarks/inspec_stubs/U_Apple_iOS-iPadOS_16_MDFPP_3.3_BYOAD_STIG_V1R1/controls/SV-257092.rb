control 'SV-257092' do
  title 'The iOS/iPadOS 16 BYOAD must be configured to either disable access to DOD data, IT systems, and user accounts or wipe managed data and apps if the EMM system detects the BYOAD device has known malicious, blocked, or prohibited applications or is configured to access nonapproved managed third-party applications stores.'
  desc 'When a BYOAD is out of compliance, DOD data and apps must be removed to protect against compromise of sensitive DOD information.

Reference: DOD policy "Use of Non-Government Mobile Devices". 3.a.(3)iii.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify the EMM system has been configured to either disable access to DOD data, IT systems, and user accounts or wipe managed data and apps if it has detected the iOS/iPadOS 16 BYOAD device has known malicious, blocked, or prohibited managed applications or is configured to access nonapproved third-party applications stores for managed apps. 

When the Work profile is wiped, all managed data and files in the Files app must be wiped as well. The exact procedure will depend on the EMM system used at the site.

If the EMM system has not been configured to either disable access to DOD data, IT systems, and user accounts or wipe managed data and apps if it has detected the iOS/iPadOS 16 BYOAD device has known malicious, blocked, or prohibited managed applications or is configured to access nonapproved third-party applications stores for managed apps, this is a finding.'
  desc 'fix', 'Configure the EMM system to either disable access to DOD data, IT systems, and user accounts or wipe managed data and apps if it has detected the iOS/iPadOS 16 BYOAD device has known malicious, blocked, or prohibited managed applications or is configured to access nonapproved third-party applications stores for managed apps. 

Note: When managed data and apps are wiped, all managed data and files in the Files app must be wiped as well. The exact procedure will depend on the EMM system used at the site.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 16 MDFPP 3.3 BYOAD'
  tag check_id: 'C-60777r904019_chk'
  tag severity: 'medium'
  tag gid: 'V-257092'
  tag rid: 'SV-257092r904021_rule'
  tag stig_id: 'AIOS-16-800090'
  tag gtitle: 'PP-BYO-000090'
  tag fix_id: 'F-60718r904020_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
