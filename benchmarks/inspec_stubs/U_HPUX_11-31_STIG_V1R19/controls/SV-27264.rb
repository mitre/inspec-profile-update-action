control 'SV-27264' do
  title 'Default system accounts must be disabled or removed.'
  desc 'Vendor accounts and software may contain backdoors that will allow unauthorized access to the system.  These backdoors are common knowledge and present a threat to system security if the account is not disabled.'
  desc 'check', 'Account/password locking is typically accomplished with the asterisk (*). System logins that never had a password use a double exclamation mark (!!) and accounts that have been locked have the valid password entry invalidated by a single exclamation mark (!) prefix.

For Trusted Mode:
Protected password database files are maintained in the /tcb/files/auth hierarchy. This directory contains other directories each named with a single letter from the alphabet. User authentication profiles are stored in these directories based on the first letter of the user account name. Next check if default system accounts (such as those for sys, bin, uucp, nuucp, daemon, smtp) have been disabled. 
# grep “u_pwd=“ /tcb/files/auth/[a-z,A-Z]/*

If any default system accounts (such as those for sys, bin, uucp, nuucp, daemon, smtp) have not been disabled, this is a finding.

For SMSE:
Check if default system accounts (such as those for sys, bin, uucp, nuucp, daemon, smtp) have been disabled. 
# cat /etc/shadow

If any default system accounts (such as those for sys, bin, uucp, nuucp, daemon, smtp) have not been disabled, this is a finding.'
  desc 'fix', 'For Trusted Mode and SMSE:
Use the System Administration Manager (SAM) or the System Management Homepage (SMH) to lock/disable or remove any enabled default system accounts.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36408r2_chk'
  tag severity: 'medium'
  tag gid: 'V-810'
  tag rid: 'SV-27264r2_rule'
  tag stig_id: 'GEN002640'
  tag gtitle: 'GEN002640'
  tag fix_id: 'F-31746r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAAC-1'
  tag cci: ['CCI-000178']
  tag nist: ['IA-5 e']
end
