control 'SV-253904' do
  title 'The Juniper EX switch must be configured to enforce a minimum 15-character password length.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password.

The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Determine if the network device or its associated authentication server enforces a minimum 15-character password length. This requirement may be verified by demonstration or configuration review. 

[edit system login password]
:
minimum-length 15;
:

If the network device or its associated authentication server does not enforce a minimum 15-character password length, this is a finding.'
  desc 'fix', 'Configure the network device or its associated authentication server to enforce a minimum 15-character password length.

set system login password minimum-length 15'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57356r843743_chk'
  tag severity: 'medium'
  tag gid: 'V-253904'
  tag rid: 'SV-253904r879601_rule'
  tag stig_id: 'JUEX-NM-000270'
  tag gtitle: 'SRG-APP-000164-NDM-000252'
  tag fix_id: 'F-57307r843744_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
