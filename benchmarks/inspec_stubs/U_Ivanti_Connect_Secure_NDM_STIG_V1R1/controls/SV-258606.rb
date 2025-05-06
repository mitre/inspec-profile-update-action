control 'SV-258606' do
  title 'The ICS must be configured to enforce password complexity by requiring that at least one special character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.'
  desc 'check', 'In the ICS Web UI, navigate to Authentication >> Auth Servers >> Administrators.
1. Verify the setting for "Password must have at least __ letters" is checked.
2. Verify the value for the setting for "Password must have at least __ special characters" is set to "1".

If the ICS does not require that at least one special character be used for passwords, this is a finding.'
  desc 'fix', 'In the ICS Web UI, navigate to Authentication >> Auth Servers >> Administrators.
1. Enable the setting for "Password must have at least __ special characters".
2. In the box, enter "1".
3. Click "Save Changes".'
  impact 0.5
  ref 'DPMS Target Ivanti Connect Secure NDM'
  tag check_id: 'C-62346r930504_chk'
  tag severity: 'medium'
  tag gid: 'V-258606'
  tag rid: 'SV-258606r930506_rule'
  tag stig_id: 'IVCS-NM-000190'
  tag gtitle: 'SRG-APP-000169-NDM-000257'
  tag fix_id: 'F-62255r930505_fix'
  tag 'documentable'
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
