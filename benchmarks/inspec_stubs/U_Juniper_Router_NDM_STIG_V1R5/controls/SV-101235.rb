control 'SV-101235' do
  title 'The Juniper router must be configured to enforce password complexity by requiring that at least one lower-case character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.'
  desc 'check', 'Review the router configuration to verify that it is compliant with this requirement as shown in the example below.

system {
   …
   …
   …
    login {
        password {
            minimum-lower-cases 1;
        }        
    }

If the router is not configured to enforce password complexity by requiring that at least one lower-case character be used, this is a finding.'
  desc 'fix', 'Configure the router to enforce password complexity by requiring that at least one lower-case character be used as shown in the example below.

[edit system login]
set password minimum-lower-cases 1'
  impact 0.5
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-90289r2_chk'
  tag severity: 'medium'
  tag gid: 'V-91135'
  tag rid: 'SV-101235r1_rule'
  tag stig_id: 'JUNI-ND-000580'
  tag gtitle: 'SRG-APP-000167-NDM-000255'
  tag fix_id: 'F-97333r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
end
