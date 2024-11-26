control 'SV-234204' do
  title 'The FortiGate device must enforce password complexity by requiring that at least one uppercase character be used.'
  desc 'Use of a complex passwords helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click System.
2. Click Settings.
3. Navigate to Password Policy.
4. Verify Password scope is enabled for Admin and Character requirements is toggled to right.
5. Verify the Uppercase value is set to 1.

If the Uppercase parameter is not set to 1, this is a finding.

or 

Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # show full-configuration system password-policy | grep -i upper-case
          # set min-upper-case-letter 1

If the min-upper-case-letter parameter is not set to 1, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click System.
2. Click Settings.
3. Navigate to Password Policy.
4. On the Password scope option, click Admin.
5. Toggle Character requirements to right.
6. Enter the Uppercase value of 1.

or

Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # config system password-policy
          # set min-upper-case-letter 1
     # end'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate NDM'
  tag check_id: 'C-37389r611799_chk'
  tag severity: 'medium'
  tag gid: 'V-234204'
  tag rid: 'SV-234204r628777_rule'
  tag stig_id: 'FGFW-ND-000225'
  tag gtitle: 'SRG-APP-000166-NDM-000254'
  tag fix_id: 'F-37354r611800_fix'
  tag 'documentable'
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
