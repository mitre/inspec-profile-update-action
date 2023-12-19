control 'SV-248583' do
  title 'OL 8 must restrict privilege elevation to authorized personnel.'
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
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52017r779313_chk'
  tag severity: 'medium'
  tag gid: 'V-248583'
  tag rid: 'SV-248583r779315_rule'
  tag stig_id: 'OL08-00-010382'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-51971r779314_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
