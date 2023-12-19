control 'SV-217278' do
  title 'The SUSE operating system SSH daemon must use privilege separation.'
  desc 'SSH daemon privilege separation causes the SSH process to drop root privileges when not needed, which would decrease the impact of software vulnerabilities in the unprivileged section.'
  desc 'check', 'Determine the version of SSH using the following command:

# ssh -V
OpenSSH_7.9p1

If the version of SSH is 7.5 or newer, this is Not Applicable.

Verify the SUSE operating system SSH daemon is configured to use privilege separation.

Check that the SUSE operating system SSH daemon performs privilege separation with the following command:

# sudo grep -i usepriv /etc/ssh/sshd_config 

UsePrivilegeSeparation yes

If the "UsePrivilegeSeparation" keyword is not set to "yes" or "sandbox", is missing, or the returned line is commented out, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system SSH daemon is configured to use privilege separation.

Uncomment the "UsePrivilegeSeparation" keyword in "/etc/ssh/sshd_config" and set the value to "yes" or "sandbox":

UsePrivilegeSeparation yes'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18506r369990_chk'
  tag severity: 'medium'
  tag gid: 'V-217278'
  tag rid: 'SV-217278r603262_rule'
  tag stig_id: 'SLES-12-030240'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-18504r369991_fix'
  tag 'documentable'
  tag legacy: ['SV-92165', 'V-77469']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
