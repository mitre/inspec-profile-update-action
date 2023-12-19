control 'SV-216089' do
  title 'User passwords must be at least 15 characters in length.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting guessing and brute-force attacks. 

Password length is one factor of several that helps to determine strength and how long it takes to crack a password. The shorter the password is, the lower the number of possible combinations that need to be tested before the password is compromised. 

Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Check the system password length setting.

# grep ^PASSLENGTH /etc/default/passwd

If PASSLENGTH is not set to 15 or more, this is a finding.'
  desc 'fix', 'The root role is required.

# pfedit /etc/default/passwd 

Locate the line containing:

PASSLENGTH

Change the line to read 

PASSLENGTH=15'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17327r372649_chk'
  tag severity: 'medium'
  tag gid: 'V-216089'
  tag rid: 'SV-216089r603268_rule'
  tag stig_id: 'SOL-11.1-040040'
  tag gtitle: 'SRG-OS-000078'
  tag fix_id: 'F-17325r372650_fix'
  tag 'documentable'
  tag legacy: ['SV-60829', 'V-47957']
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
