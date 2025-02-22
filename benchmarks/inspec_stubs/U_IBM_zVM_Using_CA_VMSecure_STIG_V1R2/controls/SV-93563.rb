control 'SV-93563' do
  title 'For FTP processing Z/VM TCP/IP FTP server Exit must be enabled.'
  desc 'Remote access services, such as those providing remote access to network devices and information systems, which lack automated monitoring capabilities, increase risk and make remote user access management difficult at best.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.'
  desc 'check', 'If there are no FTP servers’ active, this is not applicable.

Issue “SMSG” command for each FTP Server.

Query “FTAUDIT”.

If the “Exit” is not enabled, this is a finding.'
  desc 'fix', 'Include the “FTAUDIT” statement in the TCP/IP Configuration file.'
  impact 0.5
  ref 'DPMS Target z/VM Using CA VM:Secure'
  tag check_id: 'C-78443r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78857'
  tag rid: 'SV-93563r1_rule'
  tag stig_id: 'IBMZ-VM-000090'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag fix_id: 'F-85607r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
