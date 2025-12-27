control 'SV-254208' do
  title 'Nutanix AOS must enforce password complexity by requiring that at least one uppercase character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Confirm Nutanix AOS is configured to require complex passwords.
Note: The value to require a number of uppercase characters to be set is expressed as a negative number in "/etc/security/pwquality.conf".

Check the value for "ucredit" in "/etc/security/pwquality.conf" with the following command.

$ sudo grep ucredit /etc/security/pwquality.conf 
ucredit = -1

If the value of "ucredit" is not set to a negative value, this is a finding.'
  desc 'fix', 'Configure the complex password requirements by running the following command:

$ sudo salt-call state.sls security/CVM/pamCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57693r846710_chk'
  tag severity: 'medium'
  tag gid: 'V-254208'
  tag rid: 'SV-254208r846712_rule'
  tag stig_id: 'NUTX-OS-001230'
  tag gtitle: 'SRG-OS-000069-GPOS-00037'
  tag fix_id: 'F-57644r846711_fix'
  tag 'documentable'
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
