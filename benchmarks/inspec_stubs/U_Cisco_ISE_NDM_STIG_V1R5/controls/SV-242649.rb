control 'SV-242649' do
  title 'For accounts using password authentication, the Cisco ISE must enforce password complexity by requiring that at least one special character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.'
  desc 'check', 'Verify that at least one special character is required.

Show password policy

If the Cisco ISE password policy is not configured to require at least one special character, this is a finding.'
  desc 'fix', 'Configure the password policy.

password-policy special-required 1'
  impact 0.5
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45924r714255_chk'
  tag severity: 'medium'
  tag gid: 'V-242649'
  tag rid: 'SV-242649r879606_rule'
  tag stig_id: 'CSCO-NM-000440'
  tag gtitle: 'SRG-APP-000169-NDM-000257'
  tag fix_id: 'F-45881r714256_fix'
  tag 'documentable'
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
