control 'SV-54958' do
  title 'System BIOS or system controllers must have administrator accounts/passwords configured.'
  desc "A system's BIOS or system controller handles the initial startup of a system, and its configuration must be protected from unauthorized modification.  When the BIOS or system controller supports the creation of user accounts or passwords, such protections must be used and accounts/passwords only assigned to system administrators.  Failure to protect BIOS or system controller settings could result in Denial of Service or compromise of the system resulting from unauthorized configuration changes."
  desc 'check', 'Verify a supervisor or administrator password is set in the BIOS or system controller.  If a password is not configured, this is a finding.'
  desc 'fix', "Access the system's BIOS or system controller.  Configure a supervisor/administrator password."
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-48718r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36663'
  tag rid: 'SV-54958r1_rule'
  tag stig_id: 'WIN00-000011'
  tag gtitle: 'WIN00-000011'
  tag fix_id: 'F-47839r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECLP-1'
end
