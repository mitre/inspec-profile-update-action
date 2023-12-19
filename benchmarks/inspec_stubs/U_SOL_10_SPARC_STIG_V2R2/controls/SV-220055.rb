control 'SV-220055' do
  title 'The SSH daemon must be configured to only use the SSHv2 protocol.'
  desc 'SSHv1 is not a DoD-approved protocol and has many well-known vulnerability exploits.  Exploits of the SSH daemon could provide immediate root access to the system.'
  desc 'check', "Check the SSH daemon configuration for allowed protocol versions. 

# grep -i protocol /etc/ssh/sshd_config | grep -v '^#' 

If the variables Protocol 2,1 or Protocol 1 are defined on a line without a leading comment, this is a finding."
  desc 'fix', 'Edit the configuration file and modify the Protocol line to look like:

Protocol 2

Reload sshd:
kill -HUP <PID of sshd>'
  impact 0.7
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-21764r485288_chk'
  tag severity: 'high'
  tag gid: 'V-220055'
  tag rid: 'SV-220055r603265_rule'
  tag stig_id: 'GEN005500'
  tag gtitle: 'SRG-OS-000112'
  tag fix_id: 'F-21763r485289_fix'
  tag 'documentable'
  tag legacy: ['V-4295', 'SV-39817']
  tag cci: ['CCI-001941']
  tag nist: ['IA-2 (8)']
end
