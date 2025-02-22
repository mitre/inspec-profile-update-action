control 'SV-55001' do
  title 'System BIOS or system controllers must not allow user-level access.'
  desc "A system's BIOS or system controller handles the initial startup of a system, and its configuration must be protected from unauthorized modification.  When the BIOS or system controller supports the creation of user accounts or passwords, such protections must be used and accounts/passwords only assigned to system administrators.  Failure to protect BIOS or system controller settings could result in Denial of Service or compromise of the system resulting from unauthorized configuration changes."
  desc 'check', 'If the BIOS or system controller does not support user-level access in addition to supervisor/administrator access, this is NA.

If the BIOS or system controller supports user-level access in addition to supervisor/administrator access, determine whether this access is enabled.  If user-level access is enabled, this is a finding.'
  desc 'fix', "Access the system's BIOS or system controller.  Disable user-level access."
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-48731r1_chk'
  tag severity: 'medium'
  tag gid: 'V-40195'
  tag rid: 'SV-55001r1_rule'
  tag stig_id: 'WIN00-000013'
  tag gtitle: 'WN00-000002-02'
  tag fix_id: 'F-47880r2_fix'
  tag 'documentable'
  tag ia_controls: 'ECLP-1'
end
