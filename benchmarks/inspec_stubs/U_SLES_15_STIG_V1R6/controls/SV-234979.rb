control 'SV-234979' do
  title 'Audispd must take appropriate action when the SUSE operating system audit storage is full.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Verify the audit system off-loads audit records if the SUSE operating system storage volume becomes full.

Check that the records are properly off-loaded to a remote server with the following command:

> sudo grep -i "disk_full_action" /etc/audisp/audisp-remote.conf
disk_full_action = syslog

If "disk_full_action" is not set to "syslog", "single", or "halt" or the line is commented out, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to take the appropriate action if the audit storage is full.

Add, edit, or uncomment the "disk_full_action" option in "/etc/audisp/audisp-remote.conf". Set it to "syslog", "single" or "halt" as in the example below:

disk_full_action = syslog'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38167r619206_chk'
  tag severity: 'medium'
  tag gid: 'V-234979'
  tag rid: 'SV-234979r622137_rule'
  tag stig_id: 'SLES-15-030800'
  tag gtitle: 'SRG-OS-000479-GPOS-00224'
  tag fix_id: 'F-38130r619207_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
