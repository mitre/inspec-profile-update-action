control 'SV-223162' do
  title 'FireFox is configured to use a password store with or without a master password.'
  desc 'Firefox can be set to store passwords for sites visited by the user.  These individual passwords are stored in a file and can be protected by a master password. Autofill of the password can then be enabled when the site is visited.  This feature could also be used to autofill the certificate pin which could lead to compromise of DoD information.'
  desc 'check', 'Type "about:config" in the browser window. Verify that the preference name “signon.rememberSignons" is set and locked to “false”.

Criteria: If the parameter is set incorrectly, then this is a finding.

If the setting is not locked, then this is a finding.'
  desc 'fix', 'Ensure the preference “signon.rememberSignons“ is set and locked to the value of “false”.'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox'
  tag check_id: 'C-24835r531303_chk'
  tag severity: 'medium'
  tag gid: 'V-223162'
  tag rid: 'SV-223162r612236_rule'
  tag stig_id: 'DTBF160'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-24823r531304_fix'
  tag 'documentable'
  tag legacy: ['SV-16715', 'V-15776']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
