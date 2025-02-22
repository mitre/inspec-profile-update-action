control 'SV-216217' do
  title 'System BIOS or system controllers supporting password protection must have administrator accounts/passwords configured, and no others. (Intel)'
  desc "A system's BIOS or system controller handles the initial startup of a system and its configuration must be protected from unauthorized modification. When the BIOS or system controller supports the creation of user accounts or passwords, such protections must be used and accounts/passwords only assigned to system administrators. Failure to protect BIOS or system controller settings could result in denial of service or compromise of the system resulting from unauthorized configuration changes."
  desc 'check', 'This check applies to X86 compatible platforms.

On systems with a BIOS or system controller, verify a supervisor or administrator password is set. If a password is not set, this is a finding.

If the BIOS or system controller supports user-level access in addition to supervisor/administrator access, determine if this access is enabled. If so, this is a finding.'
  desc 'fix', "Consult the hardware vendor's documentation to determine how to start the system and access the BIOS controls.

Access the system's BIOS or system controller. Set a supervisor/administrator password if one has not been set. Disable a user-level password if one has been set."
  impact 0.3
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17455r373033_chk'
  tag severity: 'low'
  tag gid: 'V-216217'
  tag rid: 'SV-216217r603268_rule'
  tag stig_id: 'SOL-11.1-080120'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17453r373034_fix'
  tag 'documentable'
  tag legacy: ['SV-60877', 'V-48005']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
