control 'SV-38836' do
  title 'System BIOS or system controllers supporting password protection must have administrator accounts/passwords configured, and no others.'
  desc "A system's BIOS or system controller handles the initial startup of a system and its configuration must be protected from unauthorized modification. When the BIOS or system controller supports the creation of user accounts or passwords, such protections must be used and accounts/passwords only assigned to system administrators. Failure to protect BIOS or system controller settings could result in Denial of Service or compromise of the system resulting from unauthorized configuration changes."
  desc 'check', 'Ask the SA if a password has been given to the Service processors ADMIN account.   If a password has not been assigned to the service processor, this is a finding.'
  desc 'fix', "Access the system's service processor. Set a supervisor/administrator password if one has not been set. Disable a user-level password if one has been set."
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37097r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4246'
  tag rid: 'SV-38836r1_rule'
  tag stig_id: 'GEN008620'
  tag gtitle: 'GEN008620'
  tag fix_id: 'F-33090r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
