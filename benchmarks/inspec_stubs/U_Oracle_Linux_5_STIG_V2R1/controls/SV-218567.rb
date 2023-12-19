control 'SV-218567' do
  title 'The TFTP daemon must have mode 0755 or less permissive.'
  desc 'If TFTP runs with the setuid or setgid bit set, it may be able to write to any file or directory and may seriously impair system integrity, confidentiality, and availability.'
  desc 'check', 'Check the mode of the TFTP daemon.

Procedure:
# grep "server " /etc/xinetd.d/tftp
# ls -lL <in.tftpd binary> 

If the mode of the file is more permissive than 0755, this is a finding.'
  desc 'fix', 'Change the mode of the TFTP daemon.

Procedure:
# chmod 0755 <in.tftpd binary>'
  impact 0.7
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20042r562792_chk'
  tag severity: 'high'
  tag gid: 'V-218567'
  tag rid: 'SV-218567r603259_rule'
  tag stig_id: 'GEN005100'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-20040r562793_fix'
  tag 'documentable'
  tag legacy: ['V-848', 'SV-63163']
  tag cci: ['CCI-000225', 'CCI-001090']
  tag nist: ['AC-6', 'SC-4']
end
