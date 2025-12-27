control 'SV-248718' do
  title 'OL 8 must display the date and time of the last successful account logon upon an SSH logon.'
  desc 'Providing users with feedback on when account accesses via SSH last occurred facilitates user recognition and reporting of unauthorized account use.'
  desc 'check', 'Verify SSH provides users with feedback on when account accesses last occurred with the following command:

$ sudo grep -ir printlastlog /etc/ssh/sshd_config*

PrintLastLog yes

If the "PrintLastLog" keyword is set to "no", is missing, or is commented out, this is a finding.
If conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure SSH to provide users with feedback on when account accesses last occurred by setting the required configuration options in "/etc/pam.d/sshd" or in the "sshd_config" file used by the system ("/etc/ssh/sshd_config" will be used in the example). Note that this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor. 
 
Modify the "PrintLastLog" line in "/etc/ssh/sshd_config" to match the following: 
 
PrintLastLog yes 
 
The SSH service must be restarted for changes to "sshd_config" to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52152r858583_chk'
  tag severity: 'medium'
  tag gid: 'V-248718'
  tag rid: 'SV-248718r858584_rule'
  tag stig_id: 'OL08-00-020350'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52106r779719_fix'
  tag 'documentable'
  tag cci: ['CCI-000052']
  tag nist: ['AC-9']
end
