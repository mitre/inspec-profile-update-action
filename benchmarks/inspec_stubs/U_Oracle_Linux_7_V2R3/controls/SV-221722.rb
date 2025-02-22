control 'SV-221722' do
  title 'The Oracle Linux operating system must be configured so that all Group Identifiers (GIDs) referenced in the /etc/passwd file are defined in the /etc/group file.'
  desc 'If a user is assigned the GID of a group not existing on the system, and a group with the GID is subsequently created, the user may have unintended rights to any files associated with the group.'
  desc 'check', 'Verify all GIDs referenced in the "/etc/passwd" file are defined in the "/etc/group" file.

Check that all referenced GIDs exist with the following command:

# pwck -r

If GIDs referenced in then "/etc/passwd" file are returned as not defined in the "/etc/group" file, this is a finding.'
  desc 'fix', 'Configure the system to define all GIDs found in the "/etc/passwd" file by modifying the "/etc/group" file to add any non-existent group referenced in the "/etc/passwd" file, or change the GIDs referenced in the "/etc/passwd" file to a group that exists in "/etc/group".'
  impact 0.3
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23437r419238_chk'
  tag severity: 'low'
  tag gid: 'V-221722'
  tag rid: 'SV-221722r603260_rule'
  tag stig_id: 'OL07-00-020300'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-23426r419239_fix'
  tag 'documentable'
  tag legacy: ['V-99181', 'SV-108285']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
