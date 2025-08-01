control 'SV-226959' do
  title 'The TFTP daemon must have mode 0755 or less permissive.'
  desc 'If TFTP runs with the setuid or setgid bit set, it may be able to write to any file or directory and may seriously impair system integrity, confidentiality, and availability.'
  desc 'check', 'Check the mode of the TFTP daemon.

Procedure:

# ls -lL /usr/sbin/in.tftpd

If the mode of the file is more permissive than 0755, this is a finding.'
  desc 'fix', 'Change the mode of the TFTP daemon.

Procedure:
# chmod 0755 /usr/sbin/in.tftpd'
  impact 0.7
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29121r485204_chk'
  tag severity: 'high'
  tag gid: 'V-226959'
  tag rid: 'SV-226959r854443_rule'
  tag stig_id: 'GEN005100'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-29109r485205_fix'
  tag 'documentable'
  tag legacy: ['SV-40392', 'V-848']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
