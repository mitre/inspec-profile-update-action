control 'SV-45997' do
  title 'The SSH daemon must be configured to only use the SSHv2 protocol.'
  desc 'SSHv1 is not a DoD-approved protocol and has many well-known vulnerability exploits.  Exploits of the SSH daemon could provide immediate root access to the system.'
  desc 'check', "Locate the sshd_config file: 
# more /etc/ssh/sshd_config

Examine the file. If the variables 'Protocol 2,1’ or ‘Protocol 1’ are defined on a line without a leading comment, this is a finding."
  desc 'fix', 'Edit the sshd_config file and set the "Protocol" setting to "2". 

Restart the SSH daemon.
# /sbin/service sshd restart'
  impact 0.7
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43280r3_chk'
  tag severity: 'high'
  tag gid: 'V-4295'
  tag rid: 'SV-45997r2_rule'
  tag stig_id: 'GEN005500'
  tag gtitle: 'GEN005500'
  tag fix_id: 'F-39363r4_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
