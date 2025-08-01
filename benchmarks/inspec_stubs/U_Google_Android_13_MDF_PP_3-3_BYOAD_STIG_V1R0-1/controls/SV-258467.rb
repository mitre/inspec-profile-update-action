control 'SV-258467' do
  title 'The Google Android 13 BYOAD must be configured to either disable access to DOD data and IT systems and user accounts or wipe the work profile if the EMM system detects the Google Android 13 BYOAD device has known malicious, blocked, or prohibited applications, or configured to access nonapproved third-party applications stores in the work profile.'
  desc 'When a BYOAD is out of compliance, DOD data and apps must be removed to protect against compromise of sensitive DOD information.

Reference: DOD policy "Use of Non-Government Mobile Devices" (3.a.(3)iii).

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify the EMM system has been configured to either disable access to DOD data and IT systems and user accounts or the work profile if it has detected the Google Android 13 BYOAD device has known malicious, blocked, or prohibited managed applications, or configured to access nonapproved third-party applications stores for managed apps. The exact procedure will depend on the EMM system used at the site.

If the EMM system has not been configured to either disable access to DOD data and IT systems and user accounts or wipe the work profile if it has detected the Google Android 13 BYOAD device has known malicious, blocked, or prohibited managed applications, or configured to access nonapproved third-party applications stores for managed apps, this is a finding.'
  desc 'fix', 'Configure the EMM system to either disable access to DOD data and IT systems and user accounts or wipe the work profile if it has detected the Google Android 13 BYOAD device has known malicious, blocked, or prohibited managed applications, or configured to access nonapproved third-party applications stores for managed apps. The exact procedure will depend on the EMM system used at the site.'
  impact 0.5
  ref 'DPMS Target Google Android 13 MDFPP 3.3 BYOAD'
  tag check_id: 'C-62207r929215_chk'
  tag severity: 'medium'
  tag gid: 'V-258467'
  tag rid: 'SV-258467r929217_rule'
  tag stig_id: 'GOOG-13-800900'
  tag gtitle: 'PP-BYO-000090'
  tag fix_id: 'F-62116r929216_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
