control 'SV-258468' do
  title 'The Google Android 13 BYOAD must be configured so that the work profile is removed if the device is no longer receiving security or software updates.'
  desc 'When a BYOAD is out of compliance, DOD data and apps must be removed to protect against compromise of sensitive DOD information.

Reference: DOD policy "Use of Non-Government Mobile Devices" (3.b.(1)ii).

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify the EMM system is configured to wipe the work profile if the Google Android 13 BYOAD is no longer receiving security or software updates. The exact procedure will depend on the EMM system used at the site.

If the EMM system is not configured to wipe the work profile if the Google Android 13 BYOAD is no longer receiving security or software updates, this is a finding.'
  desc 'fix', 'Configure the EMM system so the work profile is removed if the Google Android 13 BYOAD is no longer receiving security or software updates. The exact procedure will depend on the EMM system used at the site.'
  impact 0.5
  ref 'DPMS Target Google Android 13 MDFPP 3.3 BYOAD'
  tag check_id: 'C-62208r929218_chk'
  tag severity: 'medium'
  tag gid: 'V-258468'
  tag rid: 'SV-258468r929220_rule'
  tag stig_id: 'GOOG-13-801000'
  tag gtitle: 'PP-BYO-000100'
  tag fix_id: 'F-62117r929219_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
