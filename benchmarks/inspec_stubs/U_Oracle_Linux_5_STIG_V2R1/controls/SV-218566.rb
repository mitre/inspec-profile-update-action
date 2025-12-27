control 'SV-218566' do
  title 'The TFTP daemon must operate in secure mode which provides access only to a single directory on the host file system.'
  desc 'Secure mode limits TFTP requests to a specific directory.  If TFTP is not running in secure mode, it may be able to write to any file or directory and may seriously impair system integrity, confidentiality, and availability.'
  desc 'check', '# grep server_args /etc/xinetd.d/tftp
If the "-s" parameter is not specified, this is a finding.'
  desc 'fix', 'Edit /etc/xinetd.d/tftp file and specify the "-s" parameter in server_args.'
  impact 0.7
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20041r555896_chk'
  tag severity: 'high'
  tag gid: 'V-218566'
  tag rid: 'SV-218566r603259_rule'
  tag stig_id: 'GEN005080'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20039r555897_fix'
  tag 'documentable'
  tag legacy: ['V-847', 'SV-63119']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
