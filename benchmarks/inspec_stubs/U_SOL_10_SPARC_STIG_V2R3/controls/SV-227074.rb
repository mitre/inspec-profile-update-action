control 'SV-227074' do
  title 'System BIOS or system controllers supporting password protection must have administrator accounts/passwords configured, and no others.'
  desc "A system's BIOS or system controller handles the initial startup of a system and its configuration must be protected from unauthorized modification. When the BIOS or system controller supports the creation of user accounts or passwords, such protections must be used and accounts/passwords only assigned to system administrators. Failure to protect BIOS or system controller settings could result in Denial-of-Service or compromise of the system resulting from unauthorized configuration changes."
  desc 'check', 'On systems with a BIOS or system controller, verify a supervisor or administrator password is set. If a password is not set, this is a finding.

If the BIOS or system controller supports user-level access in addition to supervisor/administrator access, determine if this access is enabled. If so, this is a finding.

The exact procedure will be hardware-dependent, and the SA should be consulted to identify the specific configuration.  In the event the BIOS or system controller is not accessible without adversely impacting (e.g., restarting) the system, the SA may be interviewed to determine compliance with the requirement.'
  desc 'fix', "Access the system's BIOS or system controller. Set a supervisor/administrator password if one has not been set. Disable a user-level password if one has been set."
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29236r485600_chk'
  tag severity: 'medium'
  tag gid: 'V-227074'
  tag rid: 'SV-227074r603265_rule'
  tag stig_id: 'GEN008620'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-29224r485601_fix'
  tag 'documentable'
  tag legacy: ['V-4246', 'SV-4246']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
