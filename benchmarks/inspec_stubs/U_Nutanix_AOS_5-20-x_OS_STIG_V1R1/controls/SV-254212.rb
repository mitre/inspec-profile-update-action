control 'SV-254212' do
  title 'Nutanix AOS must enforce password complexity by requiring that at least one special character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity or strength is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor in determining how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Special characters are those characters that are not alphanumeric. Examples include: ~ ! @ # $ % ^ *.'
  desc 'check', 'Confirm Nutanix AOS enforces password complexity by requiring that at least one special character be used.

Note: The value to require a number of special characters to be set is expressed as a negative number in "/etc/security/pwquality.conf".

Check the value for "ocredit" in "/etc/security/pwquality.conf" with the following command:

$ sudo grep ocredit /etc/security/pwquality.conf 
ocredit=-1

If the value of "ocredit" is not set to a negative value, this is a finding.'
  desc 'fix', 'Configure the operating system to enforce password complexity by requiring that at least one special character be used by setting the "ocredit" option.

Log in to a Nutanix CVM and run the following command:

$ ncli cluster edit-cvm-security-params enable-high-strength-password=true'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57697r846722_chk'
  tag severity: 'medium'
  tag gid: 'V-254212'
  tag rid: 'SV-254212r846724_rule'
  tag stig_id: 'NUTX-OS-001270'
  tag gtitle: 'SRG-OS-000266-GPOS-00101'
  tag fix_id: 'F-57648r846723_fix'
  tag 'documentable'
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
