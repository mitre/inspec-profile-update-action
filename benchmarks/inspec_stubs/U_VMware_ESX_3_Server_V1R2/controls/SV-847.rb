control 'SV-847' do
  title 'The TFTP daemon must operate in "secure mode" which provides access only to a single directory on the host file system.'
  desc 'Secure mode limits TFTP requests to a specific directory.  If TFTP is not running in secure mode, it may be able to write to any file or directory and may seriously impair system integrity, confidentiality, and availability.'
  desc 'check', 'Determine if tftpd is running in secure mode. If tftpd is running and not using secure mode, this is a finding.'
  desc 'fix', 'Configure tftpd to run in secure mode.'
  impact 0.7
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-713r2_chk'
  tag severity: 'high'
  tag gid: 'V-847'
  tag rid: 'SV-847r2_rule'
  tag stig_id: 'GEN005080'
  tag gtitle: 'GEN005080'
  tag fix_id: 'F-1001r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
