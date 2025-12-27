control 'SV-37818' do
  title 'The SSH daemon must be configured to only use the SSHv2 protocol.'
  desc 'SSHv1 is not a DoD-approved protocol and has many well-known vulnerability exploits.  Exploits of the SSH daemon could provide immediate root access to the system.'
  desc 'check', "Locate the sshd_config file: 
# more /etc/ssh/sshd_config

Examine the file. If the variables 'Protocol 2,1' or 'Protocol 1' are defined on a line without a leading comment, this is a finding.

If the SSH server is F-Secure, the variable name for SSH 1 compatibility is 'Ssh1Compatibility', not 'protocol'. If the variable 'Ssh1Compatiblity' is set to 'yes', then this is a finding."
  desc 'fix', 'Edit the sshd_config file and set the "Protocol" setting to "2". If using the F-Secure SSH server, set the "Ssh1Compatibility" setting to "no".

Restart the SSH daemon.
# /sbin/service sshd restart'
  impact 0.7
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-37020r1_chk'
  tag severity: 'high'
  tag gid: 'V-4295'
  tag rid: 'SV-37818r2_rule'
  tag stig_id: 'GEN005500'
  tag gtitle: 'GEN005500'
  tag fix_id: 'F-32288r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
