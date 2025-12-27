control 'SV-256082' do
  title 'The Riverbed NetProfiler must require that at least one special character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using public key infrastructure (PKI) is not available and for the account of last resort and root account.'
  desc 'check', 'Go to Administration >> Account Management >> User Accounts. 

Click the "Settings" button. 

Check under "Password Requirements". 

If the "Require nonalphanumeric characters" rule is not checked, this is a finding.'
  desc 'fix', 'Go to Administration >> Account Management >> User Accounts. 

Click the "Settings" button. 

Under "Password Requirements", select the "Require nonalphanumeric characters" rule.'
  impact 0.5
  ref 'DPMS Target Riverbed NetProfiler'
  tag check_id: 'C-59756r882752_chk'
  tag severity: 'medium'
  tag gid: 'V-256082'
  tag rid: 'SV-256082r882754_rule'
  tag stig_id: 'RINP-DM-000035'
  tag gtitle: 'SRG-APP-000169-NDM-000257'
  tag fix_id: 'F-59699r882753_fix'
  tag 'documentable'
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
