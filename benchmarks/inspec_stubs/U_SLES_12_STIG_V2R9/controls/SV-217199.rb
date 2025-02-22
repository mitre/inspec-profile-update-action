control 'SV-217199' do
  title 'Audispd must off-load audit records onto a different system or media from the SUSE operating system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Verify "audispd" off-loads audit records onto a different system or media from the SUSE operating system being audited.

Check if "audispd" is configured to off-load audit records onto a different system or media from the SUSE operating system by running the following command:

# sudo cat /etc/audisp/audisp-remote.conf | grep remote_server
remote_server = 192.168.1.101

If "remote_server" is not set to an external server or media, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system "/etc/audisp/audisp-remote.conf" file to off-load audit records onto a different system or media by adding or editing the following line with the correct IP address:

remote_server = [IP ADDRESS]'
  impact 0.3
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18427r369753_chk'
  tag severity: 'low'
  tag gid: 'V-217199'
  tag rid: 'SV-217199r877390_rule'
  tag stig_id: 'SLES-12-020090'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-18425r369754_fix'
  tag 'documentable'
  tag legacy: ['SV-92001', 'V-77305']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
