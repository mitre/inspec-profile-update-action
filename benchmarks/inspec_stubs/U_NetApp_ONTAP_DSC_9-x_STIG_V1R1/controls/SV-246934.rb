control 'SV-246934' do
  title 'ONTAP must off-load audit records onto a different system or media.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Use "cluster log-forwarding show" to see if remote syslogging of ONTAP audit records is configured. 

If ONTAP cannot be configured to off-load audit records onto a different system or media, this is a finding.'
  desc 'fix', 'Configure ONTAP to off-load audit records to a remote syslog server with "cluster log-forwarding create -destination <hostname_or_ip_address>".'
  impact 0.5
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50366r769132_chk'
  tag severity: 'medium'
  tag gid: 'V-246934'
  tag rid: 'SV-246934r769134_rule'
  tag stig_id: 'NAOT-AU-000002'
  tag gtitle: 'SRG-APP-000515-NDM-000325'
  tag fix_id: 'F-50320r769133_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
