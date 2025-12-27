control 'SV-221885' do
  title 'The Oracle Linux operating system must not have the Trivial File Transfer Protocol (TFTP) server package installed if not required for operational support.'
  desc 'If TFTP is required for operational support (such as the transmission of router configurations) its use must be documented with the Information System Security Officer (ISSO), restricted to only authorized personnel, and have access control rules established.'
  desc 'check', 'Verify a TFTP server has not been installed on the system.

Check to see if a TFTP server has been installed with the following command:

# yum list installed tftp-server
tftp-server-0.49-9.el7.x86_64.rpm

If TFTP is installed and the requirement for TFTP is not documented with the ISSO, this is a finding.'
  desc 'fix', 'Remove the TFTP package from the system with the following command:

# yum remove tftp-server'
  impact 0.7
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23600r419727_chk'
  tag severity: 'high'
  tag gid: 'V-221885'
  tag rid: 'SV-221885r603260_rule'
  tag stig_id: 'OL07-00-040700'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23589r419728_fix'
  tag 'documentable'
  tag legacy: ['V-99509', 'SV-108613']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
