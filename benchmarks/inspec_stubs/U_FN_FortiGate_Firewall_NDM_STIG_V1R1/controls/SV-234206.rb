control 'SV-234206' do
  title 'The FortiGate device must enforce password complexity by requiring at least one numeric character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click System.
2. Click Settings.
3. Navigate to Password Policy.
4. Verify Password scope is enabled for Admin and Character requirements is toggled to right.
5. Verify the Numbers value is set to 1.

If the Numbers parameter is not set to 1, this is a finding.

or

Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # show full-configuration system password-policy | grep -i number
          # set min-number 1

If the min-number parameter is not set to 1, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click System.
2. Click Settings.
3. Navigate to Password Policy.
4. On the Password scope option, click Admin.
5. Toggle Character requirements to right.
6. Enter the Numbers value of 1.

or

Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # config system password-policy
          # set min-number 1
     # end'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate NDM'
  tag check_id: 'C-37391r611805_chk'
  tag severity: 'medium'
  tag gid: 'V-234206'
  tag rid: 'SV-234206r628777_rule'
  tag stig_id: 'FGFW-ND-000235'
  tag gtitle: 'SRG-APP-000168-NDM-000256'
  tag fix_id: 'F-37356r611806_fix'
  tag 'documentable'
  tag cci: ['CCI-000194']
  tag nist: ['IA-5 (1) (a)']
end
