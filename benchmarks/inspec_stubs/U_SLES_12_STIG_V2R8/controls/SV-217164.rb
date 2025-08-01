control 'SV-217164' do
  title 'The SUSE operating system root account must be the only account having unrestricted access to the system.'
  desc 'If an account other than root also has a User Identifier (UID) of "0", it has root authority, giving that account unrestricted access to the entire SUSE operating system. Multiple accounts with a UID of "0" afford an opportunity for potential intruders to guess a password for a privileged account.'
  desc 'check', %q(Verify that the SUSE operating system root account is the only account with unrestricted access to the system.

Check the system for duplicate UID "0" assignments with the following command:

# awk -F: '$3 == 0 {print $1}' /etc/passwd

root

If any accounts other than root have a UID of "0", this is a finding.)
  desc 'fix', 'Change the UID of any account on the SUSE operating system, other than the root account, that has a UID of "0". 

If the account is associated with system commands or applications, the UID should be changed to one greater than "0" but less than "1000". Otherwise, assign a UID of greater than "1000" that has not already been assigned.'
  impact 0.7
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18392r369648_chk'
  tag severity: 'high'
  tag gid: 'V-217164'
  tag rid: 'SV-217164r603262_rule'
  tag stig_id: 'SLES-12-010650'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-18390r369649_fix'
  tag 'documentable'
  tag legacy: ['V-77179', 'SV-91875']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
