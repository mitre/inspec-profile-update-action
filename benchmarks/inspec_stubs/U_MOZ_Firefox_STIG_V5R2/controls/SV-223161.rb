control 'SV-223161' do
  title 'Firefox is configured to autofill passwords.'
  desc "While on the internet, it may be possible for an attacker to view the saved password files and gain access to the user's accounts on various hosts."
  desc 'check', 'In About:Config, verify that the preference name “signon.autofillForms“ is set to “false” and locked.
Criteria: If the parameter is set incorrectly, this is a finding.
If the setting is not locked, this is a finding.'
  desc 'fix', 'Ensure the preference "signon.autofillForms" is set and locked to the value of “false”.'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox'
  tag check_id: 'C-24834r531300_chk'
  tag severity: 'medium'
  tag gid: 'V-223161'
  tag rid: 'SV-223161r612236_rule'
  tag stig_id: 'DTBF150'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-24822r531301_fix'
  tag 'documentable'
  tag legacy: ['SV-16714', 'V-15775']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
