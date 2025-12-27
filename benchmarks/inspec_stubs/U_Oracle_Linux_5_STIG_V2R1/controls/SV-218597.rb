control 'SV-218597' do
  title 'The SSH daemon must be configured to only use the SSHv2 protocol.'
  desc 'SSHv1 is not a DoD-approved protocol and has many well-known vulnerability exploits.  Exploits of the SSH daemon could provide immediate root access to the system.'
  desc 'check', "Locate the sshd_config file: 
# more /etc/ssh/sshd_config

Examine the file. If the variables 'Protocol 2,1' or 'Protocol 1' are defined on a line without a leading comment, this is a finding.

If the SSH server is F-Secure, the variable name for SSH 1 compatibility is 'Ssh1Compatibility', not 'protocol'. If the variable 'Ssh1Compatiblity' is set to 'yes', then this is a finding."
  desc 'fix', 'Edit the sshd_config file and set the "Protocol" setting to "2". 

If using the F-Secure SSH server, set the "Ssh1Compatibility" setting to "no".

Restart the SSH daemon.
# /sbin/service sshd restart'
  impact 0.7
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20072r562828_chk'
  tag severity: 'high'
  tag gid: 'V-218597'
  tag rid: 'SV-218597r603259_rule'
  tag stig_id: 'GEN005500'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag fix_id: 'F-20070r562829_fix'
  tag 'documentable'
  tag legacy: ['V-4295', 'SV-63543']
  tag cci: ['CCI-000197', 'CCI-001436']
  tag nist: ['IA-5 (1) (c)', 'AC-17 (8)']
end
