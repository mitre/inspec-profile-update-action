control 'SV-221772' do
  title 'The Oracle Linux operating system must be configured so that the audit system takes appropriate action when the audit storage volume is full.'
  desc 'Taking appropriate action in case of a filled audit storage volume will minimize the possibility of losing audit records.
One method of off-loading audit logs in Oracle Linux is with the use of the audisp-remote dameon.'
  desc 'check', 'Verify the action the operating system takes if the disk the audit records are written to becomes full.

To determine the action that takes place if the disk is full on the remote server, use the following command:

# grep -i disk_full_action /etc/audisp/audisp-remote.conf
disk_full_action = single

If the value of the "disk_full_action" option is not "syslog", "single", or "halt", or the line is commented out, ask the System Administrator to indicate how the audit logs are off-loaded to a different system or storage media, and to indicate the action taken when the disk is full on the remote server.

If there is no evidence that the system is configured to off-load audit logs to a different system or storage media, or if the configuration does not take appropriate action when the disk is full on the remote server, this is a finding.'
  desc 'fix', 'Configure the action the operating system takes if the disk the audit records are written to becomes full.

Uncomment or edit the "disk_full_action" option in "/etc/audisp/audisp-remote.conf" and set it to "syslog", "single", or "halt", such as the following line:

disk_full_action = single'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-36291r602467_chk'
  tag severity: 'medium'
  tag gid: 'V-221772'
  tag rid: 'SV-221772r853686_rule'
  tag stig_id: 'OL07-00-030320'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-36255r602468_fix'
  tag 'documentable'
  tag legacy: ['SV-108387', 'V-99283']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
