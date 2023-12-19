control 'SV-258614' do
  title 'The ICS must be configured to enforce a minimum 15-character password length.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password.

The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'In the ICS Web UI, navigate to Authentication >> Auth Servers >> Administrators.

If the minimum length is not 15 characters, this is a finding.'
  desc 'fix', 'In the ICS Web UI, navigate to Authentication >> Auth Servers >> Administrators.
1. For minimum length, type "15".
2. Click "Save Changes".'
  impact 0.5
  ref 'DPMS Target Ivanti Connect Secure NDM'
  tag check_id: 'C-62354r930528_chk'
  tag severity: 'medium'
  tag gid: 'V-258614'
  tag rid: 'SV-258614r930530_rule'
  tag stig_id: 'IVCS-NM-000440'
  tag gtitle: 'SRG-APP-000164-NDM-000252'
  tag fix_id: 'F-62263r930529_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
