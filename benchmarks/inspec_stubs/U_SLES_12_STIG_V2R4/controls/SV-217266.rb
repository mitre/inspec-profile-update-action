control 'SV-217266' do
  title 'The SUSE operating system must display the date and time of the last successful account logon upon an SSH logon.'
  desc 'Providing users with feedback on when account accesses via SSH last occurred facilitates user recognition and reporting of unauthorized account use.'
  desc 'check', 'Verify all remote connections via SSH to the SUSE operating system display feedback on when account accesses last occurred.

Check that "PrintLastLog" keyword in the sshd daemon configuration file is used and set to "yes" with the following command:

# sudo grep -i printlastlog /etc/ssh/sshd_config
PrintLastLog yes

If the "PrintLastLog" keyword is set to "no", is missing, or is commented out, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to provide users with feedback on when account accesses last occurred.

Add or edit the following lines in the "/etc/ssh/sshd_config" file:

PrintLastLog yes'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18494r369954_chk'
  tag severity: 'medium'
  tag gid: 'V-217266'
  tag rid: 'SV-217266r603262_rule'
  tag stig_id: 'SLES-12-030130'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-18492r369955_fix'
  tag 'documentable'
  tag legacy: ['V-77447', 'SV-92143']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
