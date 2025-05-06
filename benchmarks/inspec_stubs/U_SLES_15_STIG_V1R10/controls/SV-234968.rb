control 'SV-234968' do
  title 'Audispd must off-load audit records onto a different system or media from the SUSE operating system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Verify "audispd" off-loads audit records onto a different system or media from the SUSE operating system being audited.

Check if "audispd" is configured to off-load audit records onto a different system or media from the SUSE operating system by running the following command:

> sudo grep remote_server /etc/audisp/audisp-remote.conf
remote_server = 192.168.1.101

If "remote_server" is not set to an external server or media, or is commented out, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system "/etc/audisp/audisp-remote.conf" file to off-load audit records onto a different system or media by adding or editing the following line with the correct IP address:

remote_server = [IP ADDRESS]'
  impact 0.3
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38156r619173_chk'
  tag severity: 'low'
  tag gid: 'V-234968'
  tag rid: 'SV-234968r877390_rule'
  tag stig_id: 'SLES-15-030690'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-38119r619174_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
