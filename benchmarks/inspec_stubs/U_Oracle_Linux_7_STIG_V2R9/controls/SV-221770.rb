control 'SV-221770' do
  title 'The Oracle Linux operating system must off-load audit records onto a different system or media from the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.

'
  desc 'check', 'Verify the operating system off-loads audit records onto a different system or media from the system being audited.

To determine the remote server that the records are being sent to, use the following command:

# grep -i remote_server /etc/audisp/audisp-remote.conf
remote_server = 10.0.21.1

If a remote server is not configured, or the line is commented out, ask the System Administrator to indicate how the audit logs are off-loaded to a different system or media. 

If there is no evidence that the audit logs are being off-loaded to another system or media, this is a finding.'
  desc 'fix', 'Configure the operating system to off-load audit records onto a different system or media from the system being audited.

Set the remote server option in "/etc/audisp/audisp-remote.conf" with the IP address of the log aggregation server.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23485r419382_chk'
  tag severity: 'medium'
  tag gid: 'V-221770'
  tag rid: 'SV-221770r853684_rule'
  tag stig_id: 'OL07-00-030300'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-23474r419383_fix'
  tag satisfies: ['SRG-OS-000342-GPOS-00133', 'SRG-OS-000479-GPOS-00224']
  tag 'documentable'
  tag legacy: ['V-99279', 'SV-108383']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
