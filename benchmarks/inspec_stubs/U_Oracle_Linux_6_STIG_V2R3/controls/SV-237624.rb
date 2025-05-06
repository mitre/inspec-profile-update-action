control 'SV-237624' do
  title 'The Oracle Linux operating system must restrict privilege elevation to authorized personnel.'
  desc 'The sudo command allows a user to execute programs with elevated (administrator) privileges. It prompts the user for their password and confirms your request to execute a command by checking a file, called sudoers. If the "sudoers" file is not configured correctly, any user defined on the system can initiate privileged actions on the target system.'
  desc 'check', %q(Verify the "sudoers" file restricts sudo access to authorized personnel.
$ sudo grep -iw 'ALL' /etc/sudoers /etc/sudoers.d/*

If the either of the following entries are returned, this is a finding:
ALL     ALL=(ALL) ALL
ALL     ALL=(ALL:ALL) ALL)
  desc 'fix', 'Remove the following entries from the sudoers file:
ALL     ALL=(ALL) ALL
ALL     ALL=(ALL:ALL) ALL'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-40843r646941_chk'
  tag severity: 'medium'
  tag gid: 'V-237624'
  tag rid: 'SV-237624r646943_rule'
  tag stig_id: 'OL6-00-000535'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-40806r646942_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
