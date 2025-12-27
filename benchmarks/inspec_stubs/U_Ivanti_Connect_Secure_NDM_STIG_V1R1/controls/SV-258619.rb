control 'SV-258619' do
  title 'The ICS must be configured to enforce password complexity by requiring that at least one uppercase character be used.'
  desc 'Use of a complex passwords helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password is, the greater the number of possible combinations that need to be tested before the password is compromised.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.'
  desc 'check', 'In the ICS Web UI, navigate to Authentication >> Auth Servers >> Administrators.
1. Verify the setting for "Password must have at least __ letters" is checked.
2. Verify the setting for "Password must have mix of UPPERCASE and lowercase letters" is checked.
3. Verify value for the setting for "Password must have at least __ letters" is set to "2".

If the ICS is not configured to enforce password complexity by requiring that at least one upper-case character be used, this is a finding.'
  desc 'fix', 'In the ICS Web UI, navigate to Authentication >> Auth Servers >> Administrators.
1. If the setting for "Password must have at least __ letters".
2. In the box, enter "2".
3. Check the box for "Password must have mix of UPPERCASE and lowercase letters".
4. Click "Save Changes".'
  impact 0.5
  ref 'DPMS Target Ivanti Connect Secure NDM'
  tag check_id: 'C-62359r930543_chk'
  tag severity: 'medium'
  tag gid: 'V-258619'
  tag rid: 'SV-258619r930545_rule'
  tag stig_id: 'IVCS-NM-000490'
  tag gtitle: 'SRG-APP-000166-NDM-000254'
  tag fix_id: 'F-62268r930544_fix'
  tag 'documentable'
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
