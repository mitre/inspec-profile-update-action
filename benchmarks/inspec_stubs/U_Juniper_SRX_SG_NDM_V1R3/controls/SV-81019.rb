control 'SV-81019' do
  title 'For nonlocal maintenance sessions using SSH, the Juniper SRX Services Gateway must securely configure SSHv2 Message Authentication Code (MAC) algorithms to protect the integrity of maintenance and diagnostic communications.'
  desc 'To protect the integrity of nonlocal maintenance sessions, SSHv2 with MAC algorithms for integrity checking must be configured. 

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. 

The SSHv2 protocol suite includes Layer 7 protocols such as SCP and SFTP which can be used for secure file transfers.'
  desc 'check', 'Verify SSHv2 and MAC algorithms for integrity checking.

[edit]
show system services ssh

If SSHv2 and integrity options are not configured in compliance with DoD requirements, this is a finding.'
  desc 'fix', 'Configure SSH integrity options to comply with DoD requirements.

[edit]
set system services ssh protocol-version v2
set system services ssh macs hmac-sha2-512
set system services ssh macs hmac-sha2-256
set system services ssh macs hmac-sha1
set system services ssh macs hmac-sha1-96'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-67175r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66529'
  tag rid: 'SV-81019r1_rule'
  tag stig_id: 'JUSX-DM-000147'
  tag gtitle: 'SRG-APP-000411-NDM-000330'
  tag fix_id: 'F-72605r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002890']
  tag nist: ['MA-4 (6)']
end
