control 'SV-223168' do
  title 'Background submission of information to Mozilla must be disabled.'
  desc 'There should be no background submission of technical and other information from DoD computers to Mozilla with portions posted publically.'
  desc 'check', 'Type "about:config" in the address bar of the browser.
Verify that the preference "datareporting.policy.dataSubmissionEnabled" is set and locked to "false". Otherwise, this is a finding.'
  desc 'fix', 'Ensure the preferences "datareporting.policy.dataSubmissionEnabled" is set and locked to "false".'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox'
  tag check_id: 'C-24841r531321_chk'
  tag severity: 'medium'
  tag gid: 'V-223168'
  tag rid: 'SV-223168r612236_rule'
  tag stig_id: 'DTBF190'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-24829r531322_fix'
  tag 'documentable'
  tag legacy: ['SV-93759', 'V-79053']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
