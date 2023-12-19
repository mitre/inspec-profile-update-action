control 'SV-204621' do
  title 'The Red Hat Enterprise Linux operating system must not have the Trivial File Transfer Protocol (TFTP) server package installed if not required for operational support.'
  desc 'If TFTP is required for operational support (such as the transmission of router configurations) its use must be documented with the Information System Security Officer (ISSO), restricted to only authorized personnel, and have access control rules established.'
  desc 'check', 'Verify a TFTP server has not been installed on the system.

Check to see if a TFTP server has been installed with the following command:

# yum list installed tftp-server
tftp-server-0.49-9.el7.x86_64.rpm

If TFTP is installed and the requirement for TFTP is not documented with the ISSO, this is a finding.'
  desc 'fix', 'Remove the TFTP package from the system with the following command:

# yum remove tftp-server'
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4745r89055_chk'
  tag severity: 'high'
  tag gid: 'V-204621'
  tag rid: 'SV-204621r853996_rule'
  tag stig_id: 'RHEL-07-040700'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-4745r89056_fix'
  tag 'documentable'
  tag legacy: ['SV-86925', 'V-72301']
  tag cci: ['CCI-000318', 'CCI-000368', 'CCI-001812', 'CCI-001813', 'CCI-001814']
  tag nist: ['CM-3 f', 'CM-6 c', 'CM-11 (2)', 'CM-5 (1) (a)', 'CM-5 (1)']
end
