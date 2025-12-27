control 'SV-208806' do
  title 'Default operating system accounts, other than root, must be locked.'
  desc 'Disabling authentication for default system accounts makes it more difficult for attackers to make use of them to compromise a system.'
  desc 'check', %q(To obtain a listing of all users and the contents of their shadow password field, run the command:

$ awk -F: '$1 !~ /^root$/ && $2 !~ /^[!*]/ {print $1 ":" $2}' /etc/shadow

Identify the operating system accounts from this listing. These will primarily be the accounts with UID numbers less than 500, other than root. If any default operating system account (other than root) has a valid password hash, this is a finding.)
  desc 'fix', 'Some accounts are not associated with a human user of the system, and exist to perform some administrative function. An attacker should not be able to log into these accounts. 

Disable logon access to these accounts with the command: 

# passwd -l [SYSACCT]'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9059r357398_chk'
  tag severity: 'medium'
  tag gid: 'V-208806'
  tag rid: 'SV-208806r603263_rule'
  tag stig_id: 'OL6-00-000029'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9059r357399_fix'
  tag 'documentable'
  tag legacy: ['SV-64937', 'V-50731']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
