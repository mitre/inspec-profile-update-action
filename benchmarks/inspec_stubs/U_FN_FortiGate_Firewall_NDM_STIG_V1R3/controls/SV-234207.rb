control 'SV-234207' do
  title 'The FortiGate device must enforce password complexity by requiring that at least one special character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click System.
2. Click Settings.
3. Navigate to Password Policy.
4. Verify Password scope is enabled for Admin and Character requirements is toggled to right.
5. Verify the Special value is set to 1 or greater.

If the Special parameter is not set to 1 or greater, this is a finding.

or

Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # show full-configuration system password-policy | grep -i non-alphanumeric

If the min-non-alphanumeric parameter is not set to 1 greater, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click System.
2. Click Settings.
3. Navigate to Password Policy.
4. On the Password scope option, click Admin.
5. Toggle Character requirements to right.
6. Enter the Special value of 1 or greater.

or

Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following commands:
     # config system password-policy
          # set min-non-alphanumeric 1 (or greater)
     # end'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall NDM'
  tag check_id: 'C-37392r835197_chk'
  tag severity: 'medium'
  tag gid: 'V-234207'
  tag rid: 'SV-234207r835199_rule'
  tag stig_id: 'FGFW-ND-000240'
  tag gtitle: 'SRG-APP-000169-NDM-000257'
  tag fix_id: 'F-37357r835198_fix'
  tag 'documentable'
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
