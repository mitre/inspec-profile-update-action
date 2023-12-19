control 'SV-39817' do
  title 'The SSH daemon must be configured to only use the SSHv2 protocol.'
  desc 'SSHv1 is not a DoD-approved protocol and has many well-known vulnerability exploits.  Exploits of the SSH daemon could provide immediate root access to the system.'
  desc 'fix', 'Edit the configuration file and modify the Protocol line to look like:

Protocol 2

Reload sshd:
kill -HUP <PID of sshd>'
  impact 0.7
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'high'
  tag gid: 'V-4295'
  tag rid: 'SV-39817r1_rule'
  tag stig_id: 'GEN005500'
  tag gtitle: 'GEN005500'
  tag fix_id: 'F-34272r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1, DCPP-1'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
