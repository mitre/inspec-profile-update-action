control 'SV-37925' do
  title 'System BIOS or system controllers supporting password protection must have administrator accounts/passwords configured, and no others.'
  desc "A system's BIOS or system controller handles the initial startup of a system and its configuration must be protected from unauthorized modification. When the BIOS or system controller supports the creation of user accounts or passwords, such protections must be used and accounts/passwords only assigned to system administrators. Failure to protect BIOS or system controller settings could result in Denial of Service or compromise of the system resulting from unauthorized configuration changes."
  desc 'check', 'On systems with a BIOS or system controller, verify a supervisor or administrator password is set. If a password is not set, this is a finding.

If the BIOS or system controller supports user-level access in addition to supervisor/administrator access, determine if this access is enabled. If so, this is a finding.'
  desc 'fix', "Access the system's BIOS or system controller. Set a supervisor/administrator password if one has not been set. Disable a user-level password if one has been set."
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-37163r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4246'
  tag rid: 'SV-37925r1_rule'
  tag stig_id: 'GEN008620'
  tag gtitle: 'GEN008620'
  tag fix_id: 'F-4157r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
