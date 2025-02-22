control 'SV-253102' do
  title 'If the Trivial File Transfer Protocol (TFTP) server is required, the TOSS TFTP daemon must be configured to operate in secure mode.'
  desc 'Restricting TFTP to a specific directory prevents remote users from copying, transferring, or overwriting system files.'
  desc 'check', 'Verify the TFTP daemon is configured to operate in secure mode with the following commands:

$ sudo yum list installed tftp-server

tftp-server.x86_64 x.x-x.el8 

If a TFTP server is not installed, this is Not Applicable.

If a TFTP server is installed, check for the server arguments with the following command: 

$ sudo grep server_args /etc/xinetd.d/tftp

server_args = -s /var/lib/tftpboot

If the "server_args" line does not have a "-s" option, and a subdirectory is not assigned, this is a finding.'
  desc 'fix', 'Configure the TFTP daemon to operate in secure mode by adding the following line to "/etc/xinetd.d/tftp" (or modify the line to have the required value):

server_args = -s /var/lib/tftpboot'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56555r824976_chk'
  tag severity: 'medium'
  tag gid: 'V-253102'
  tag rid: 'SV-253102r824978_rule'
  tag stig_id: 'TOSS-04-040600'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56505r824977_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
