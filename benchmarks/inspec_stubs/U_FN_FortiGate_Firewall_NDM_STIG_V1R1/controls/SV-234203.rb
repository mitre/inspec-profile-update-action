control 'SV-234203' do
  title 'The FortiGate device must enforce a minimum 15-character password length.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password.

The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click System.
2. Click Settings.
3. Navigate to Password Policy.
4. Verify Password scope is enabled for Admin.
5. Verify the Minimum length is set to 15.

If the Password scope is OFF and the Minimum length is not set to 15, this is a finding.

or 

Log in to the FortiGate GUI with Super-Admin privilege:

1. Open a CLI console, via SSH or available from the GUI
2. Run the following command:
     # show full-configuration system password-policy | grep -i minimum
          set minimum-length 15

If the minimum-length parameter is not set to 15, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click System.
2. Click Settings.
3. Navigate to Password Policy.
4. On the Password scope option, click Admin.
5. Enter the Minimum length value of 15.

or

Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # config system password-policy
           # set status enable
          # set minimum-length 15
     # end--+'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate NDM'
  tag check_id: 'C-37388r611796_chk'
  tag severity: 'medium'
  tag gid: 'V-234203'
  tag rid: 'SV-234203r628777_rule'
  tag stig_id: 'FGFW-ND-000220'
  tag gtitle: 'SRG-APP-000164-NDM-000252'
  tag fix_id: 'F-37353r611797_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
