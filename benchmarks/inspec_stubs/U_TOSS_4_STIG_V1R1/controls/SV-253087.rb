control 'SV-253087' do
  title 'TOSS must enforce password complexity by requiring that at least one special character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity or strength is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

TOSS utilizes "pwquality" as a mechanism to enforce password complexity. Note that to require special characters without degrading the "minlen" value, the credit value must be expressed as a negative number in "/etc/security/pwquality.conf."'
  desc 'check', 'Verify the value for "ocredit" in "/etc/security/pwquality.conf" with the following command:

$ sudo grep ocredit /etc/security/pwquality.conf 
ocredit = -1 

If the value of "ocredit" is a positive number or is commented out, this is a finding.'
  desc 'fix', 'Configure the operating system to enforce password complexity by requiring that at least one special character be used by setting the "ocredit" option.

Add the following line to /etc/security/pwquality.conf (or modify the line to have the required value):

ocredit = -1'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56540r824931_chk'
  tag severity: 'medium'
  tag gid: 'V-253087'
  tag rid: 'SV-253087r824933_rule'
  tag stig_id: 'TOSS-04-040350'
  tag gtitle: 'SRG-OS-000266-GPOS-00101'
  tag fix_id: 'F-56490r824932_fix'
  tag 'documentable'
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
