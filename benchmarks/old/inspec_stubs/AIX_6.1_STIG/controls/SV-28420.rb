control 'SV-28420' do
  title 'The TFTP daemon must operate in "secure mode" which provides access only to a single directory on the host file system.'
  desc 'Secure mode limits TFTP requests to a specific directory.  If TFTP is not running in secure mode, it may be able to write to any file or directory and may seriously impair system integrity, confidentiality, and availability.'
  desc 'check', 'If the system is not running tftp, this is not applicable.

Determine if tftpd is running in secure mode.

# more /etc/tftpaccess.ctl

If the file does not exist, this is a finding.  If the file does not contain an entry restricting access to the tftp user home directory, this is a finding.  If other configuration is in the file, this is a finding.'
  desc 'fix', 'Edit /etc/tftpaccess.ctl to only contain an entry restricting access to the tftp user home directory.'
  impact 0.7
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-28685r2_chk'
  tag severity: 'high'
  tag gid: 'V-847'
  tag rid: 'SV-28420r1_rule'
  tag stig_id: 'GEN005080'
  tag gtitle: 'GEN005080'
  tag fix_id: 'F-25711r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
