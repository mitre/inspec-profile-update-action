control 'SV-86155' do
  title 'The CA API Gateway must enforce a minimum 15-character password length.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password.

The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Verify the CA API Gateway configuration files for passwords (/etc/login.defs, /etc/pam.d/password, /etc/pam.d/password-auth-ac, /etc/pam.d/system-auth, and /etc/pam.d/system-auth-ac) each have this line: 

PASS_MIN_LEN 15.

If the CA API Gateway configuration files for passwords (/etc/login.defs, /etc/pam.d/password, /etc/pam.d/password-auth-ac, /etc/pam.d/system-auth, and /etc/pam.d/system-auth-ac) do not have the line requiring minimum 15-character password length, this is a finding.'
  desc 'fix', 'In order to change the default setting: 

- Log in to Gateway via SSH.
- Open /etc/login.defs.
- Change the value for PASS_MIN_LENGTH to desired value.

Then:

- Change the PASS_MIN_LENGTH field to desired value in the following files:
-- /etc/pam.d/password-auth
-- /etc/pam.d/password-auth-ac
-- /etc/pam.d/system-auth
-- /etc/pam.d/system-auth-ac

Note: Must be a value of "15" or greater.'
  impact 0.5
  ref 'DPMS Target CA API Gateway NDM'
  tag check_id: 'C-71903r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71531'
  tag rid: 'SV-86155r1_rule'
  tag stig_id: 'CAGW-DM-000160'
  tag gtitle: 'SRG-APP-000164-NDM-000252'
  tag fix_id: 'F-77851r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
