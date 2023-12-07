control 'SV-37560' do
  title 'The TFTP daemon must operate in "secure mode" which provides access only to a single directory on the host file system.'
  desc 'Secure mode limits TFTP requests to a specific directory.  If TFTP is not running in secure mode, it may be able to write to any file or directory and may seriously impair system integrity, confidentiality, and availability.'
  desc 'fix', 'Edit /etc/xinetd.d/tftp file and specify the "-s" parameter in server_args.'
  impact 0.7
  ref 'DPMS Target Red Hat 5'
  tag severity: 'high'
  tag gid: 'V-847'
  tag rid: 'SV-37560r1_rule'
  tag stig_id: 'GEN005080'
  tag gtitle: 'GEN005080'
  tag fix_id: 'F-31470r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
