control 'SV-252937' do
  title 'The root account must be the only account having unrestricted access to the TOSS system.'
  desc 'If an account other than root also has a User Identifier (UID) of "0", it has root authority, giving that account unrestricted access to the entire operating system. Multiple accounts with a UID of "0" afford an opportunity for potential intruders to guess a password for a privileged account.'
  desc 'check', %q(Check the system for duplicate UID "0" assignments with the following command:

$ sudo awk -F: '$3 == 0 {print $1}' /etc/passwd

If any accounts other than root have a UID of "0", this is a finding.)
  desc 'fix', 'Change the UID of any account on the system, other than root, that has a UID of "0." 

If the account is associated with system commands or applications, the UID should be changed to one greater than "0" but less than "1000." Otherwise, assign a UID of greater than "1000" that has not already been assigned.'
  impact 0.7
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56390r824133_chk'
  tag severity: 'high'
  tag gid: 'V-252937'
  tag rid: 'SV-252937r824135_rule'
  tag stig_id: 'TOSS-04-010350'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56340r824134_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
