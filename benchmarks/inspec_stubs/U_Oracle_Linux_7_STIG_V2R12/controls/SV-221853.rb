control 'SV-221853' do
  title 'The Oracle Linux operating system must display the date and time of the last successful account logon upon an SSH logon.'
  desc 'Providing users with feedback on when account accesses via SSH last occurred facilitates user recognition and reporting of unauthorized account use.'
  desc 'check', 'Verify SSH provides users with feedback on when account accesses last occurred.

Check that "PrintLastLog" keyword in the sshd daemon configuration file is used and set to "yes" with the following command:

# grep -i printlastlog /etc/ssh/sshd_config
PrintLastLog yes

If the "PrintLastLog" keyword is set to "no", is missing, or is commented out, this is a finding.'
  desc 'fix', 'Configure SSH to provide users with feedback on when account accesses last occurred by setting the required configuration options in "/etc/pam.d/sshd" or in the "sshd_config" file used by the system ("/etc/ssh/sshd_config" will be used in the example) (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor).

Modify the "PrintLastLog" line in "/etc/ssh/sshd_config" to match the following:

PrintLastLog yes

The SSH service must be restarted for changes to "sshd_config" to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23568r419631_chk'
  tag severity: 'medium'
  tag gid: 'V-221853'
  tag rid: 'SV-221853r858451_rule'
  tag stig_id: 'OL07-00-040360'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23557r419632_fix'
  tag 'documentable'
  tag legacy: ['V-99445', 'SV-108549']
  tag cci: ['CCI-000052']
  tag nist: ['AC-9']
end
