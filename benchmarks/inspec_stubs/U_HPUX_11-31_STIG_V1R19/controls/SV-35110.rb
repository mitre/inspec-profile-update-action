control 'SV-35110' do
  title 'The TFTP daemon must operate in "secure mode" which provides access only to a single directory on the host file system.'
  desc 'Secure mode limits TFTP requests to a specific directory.  If TFTP is not running in secure mode, it may be able to write to any file or directory and may seriously impair system integrity, confidentiality, and availability.'
  desc 'check', %q(Determine if the TFTP daemon is installed, started, and running in secure mode. 
# cat /etc/inetd.conf | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[  \t]*//'  | grep -v "^#" | cut -f 6,7 -d " " | grep -i tftp

If the tftpd process is not configured with exactly one path argument 
(example: "/usr/lbin/tftpd  tftpd"), this is a finding.)
  desc 'fix', 'Edit /etc/inetd.conf and add one path argument, representing 
the TFTP root directory, to the tftpd command.'
  impact 0.7
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36593r1_chk'
  tag severity: 'high'
  tag gid: 'V-847'
  tag rid: 'SV-35110r1_rule'
  tag stig_id: 'GEN005080'
  tag gtitle: 'GEN005080'
  tag fix_id: 'F-31960r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
