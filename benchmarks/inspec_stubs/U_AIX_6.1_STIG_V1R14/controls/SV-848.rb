control 'SV-848' do
  title 'The TFTP daemon must have mode 0755 or less permissive.'
  desc 'If TFTP runs with the setuid or setgid bit set, it may be able to write to any file or directory and may seriously impair system integrity, confidentiality, and availability.'
  desc 'check', 'Check the mode of the TFTP daemon.

Procedure:
# find / -name "*tftpd" -print 
# ls -lL <file location> 

If the mode of the file is more permissive than 0755, this is a finding.'
  desc 'fix', 'Change the mode of the TFTP daemon.

Procedure:
# chmod 0755 <tftp server>'
  impact 0.7
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-714r2_chk'
  tag severity: 'high'
  tag gid: 'V-848'
  tag rid: 'SV-848r2_rule'
  tag stig_id: 'GEN005100'
  tag gtitle: 'GEN005100'
  tag fix_id: 'F-1002r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECPA-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
