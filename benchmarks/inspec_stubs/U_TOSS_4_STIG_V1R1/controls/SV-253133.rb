control 'SV-253133' do
  title 'TOSS must restrict privilege elevation to authorized personnel.'
  desc 'The sudo command allows a user to execute programs with elevated (administrator) privileges. It prompts the user for their password and confirms the request to execute a command by checking a file, called sudoers. If the "sudoers" file is not configured correctly, any user defined on the system can initiate privileged actions on the target system.'
  desc 'check', %q(Verify the "sudoers" file restricts sudo access to authorized personnel.

$ sudo grep -iwr 'ALL[[:blank:]]\+ALL' /etc/sudoers /etc/sudoers.d

If the either of the following entries are returned, this is a finding:
ALL     ALL=(ALL) ALL
ALL     ALL=(ALL:ALL) ALL)
  desc 'fix', 'Remove the following entries from the sudoers file:
ALL     ALL=(ALL) ALL
ALL     ALL=(ALL:ALL) ALL'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56586r825069_chk'
  tag severity: 'medium'
  tag gid: 'V-253133'
  tag rid: 'SV-253133r825071_rule'
  tag stig_id: 'TOSS-04-040920'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56536r825070_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
