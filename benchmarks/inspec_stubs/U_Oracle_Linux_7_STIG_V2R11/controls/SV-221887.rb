control 'SV-221887' do
  title 'The Oracle Linux operating system must be configured so that if the Trivial File Transfer Protocol (TFTP) server is required, the TFTP daemon is configured to operate in secure mode.'
  desc 'Restricting TFTP to a specific directory prevents remote users from copying, transferring, or overwriting system files.'
  desc 'check', 'Verify the TFTP daemon is configured to operate in secure mode.

Check to see if a TFTP server has been installed with the following commands:

# yum list installed tftp-server
tftp-server.x86_64 x.x-x.el7

If a TFTP server is not installed, this is Not Applicable.

If a TFTP server is installed, check for the server arguments with the following command: 

# grep server_args /etc/xinetd.d/tftp
server_args = -s /var/lib/tftpboot

If the "server_args" line does not have a "-s" option and a subdirectory is not assigned, this is a finding.'
  desc 'fix', 'Configure the TFTP daemon to operate in secure mode by adding the following line to "/etc/xinetd.d/tftp" (or modify the line to have the required value):

server_args = -s /var/lib/tftpboot'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23602r419733_chk'
  tag severity: 'medium'
  tag gid: 'V-221887'
  tag rid: 'SV-221887r603260_rule'
  tag stig_id: 'OL07-00-040720'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23591r419734_fix'
  tag 'documentable'
  tag legacy: ['SV-108617', 'V-99513']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
