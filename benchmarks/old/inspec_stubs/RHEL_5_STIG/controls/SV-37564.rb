control 'SV-37564' do
  title 'The TFTP daemon must have mode 0755 or less permissive.'
  desc 'If TFTP runs with the setuid or setgid bit set, it may be able to write to any file or directory and may seriously impair system integrity, confidentiality, and availability.'
  desc 'fix', 'Change the mode of the TFTP daemon.

Procedure:
# chmod 0755 <in.tftpd binary>'
  impact 0.7
  ref 'DPMS Target Red Hat 5'
  tag severity: 'high'
  tag gid: 'V-848'
  tag rid: 'SV-37564r1_rule'
  tag stig_id: 'GEN005100'
  tag gtitle: 'GEN005100'
  tag fix_id: 'F-31473r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECPA-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
