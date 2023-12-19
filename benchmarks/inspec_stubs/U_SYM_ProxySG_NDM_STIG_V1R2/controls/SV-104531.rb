control 'SV-104531' do
  title 'Symantec ProxySG must be configured to enforce a minimum 15-character password length for local accounts.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password.

The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Verify the minimum password length is set to at least 15 characters.

At the CLI, type:

Show Security

Look for value of the "Minimum Password Length:".

If Symantec ProxySG is not configured to enforce a minimum 15-character password length for local accounts, this is a finding.'
  desc 'fix', 'In order to set the minimum password length 15 characters.

1. Log on to the Symantec ProxySG SSH CLI.
2. Type "enable", enter the enable password.
3. Type "configure" and press "Enter".
4. Type "security password-min-len 15" and press "Enter".'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG NDM'
  tag check_id: 'C-93891r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94701'
  tag rid: 'SV-104531r1_rule'
  tag stig_id: 'SYMP-NM-000250'
  tag gtitle: 'SRG-APP-000164-NDM-000252'
  tag fix_id: 'F-100819r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
