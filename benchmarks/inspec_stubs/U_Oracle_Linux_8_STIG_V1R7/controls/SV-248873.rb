control 'SV-248873' do
  title 'The Trivial File Transfer Protocol (TFTP) server package must not be installed if not required for OL 8 operational support.'
  desc 'If TFTP is required for operational support (such as the transmission of router configurations) its use must be documented with the Information System Security Officer (ISSO), restricted to only authorized personnel, and have access control rules established.'
  desc 'check', 'Verify a TFTP server has not been installed on the system with the following command: 
 
$ sudo yum list installed tftp-server 
 
tftp-server.x86_64 5.2-24.el8 
 
If TFTP is installed and the requirement for TFTP is not documented with the ISSO, this is a finding.'
  desc 'fix', 'Remove the TFTP package from the system with the following command: 
 
$ sudo yum remove tftp-server'
  impact 0.7
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52307r780183_chk'
  tag severity: 'high'
  tag gid: 'V-248873'
  tag rid: 'SV-248873r780185_rule'
  tag stig_id: 'OL08-00-040190'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52261r780184_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
