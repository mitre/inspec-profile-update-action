control 'SV-4295' do
  title 'The SSH daemon must be configured to only use the SSHv2 protocol.'
  desc 'SSHv1 is not a DoD-approved protocol and has many well-known vulnerability exploits.  Exploits of the SSH daemon could provide immediate root access to the system.'
  desc 'check', %q(Examine the sshd configuration file.
cat /opt/ssh/etc/sshd_config | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' | grep -v '^#' | grep -i "Protocol"

If Protocol 2,1 or Protocol 1 are defined on a line without a leading comment, this is a finding.)
  desc 'fix', 'Edit the configuration file and modify the Protocol line.

Protocol 2

Restart sshd:

/sbin/init.d/secsh stop
/sbin/init.d/secsh start'
  impact 0.7
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-1875r2_chk'
  tag severity: 'high'
  tag gid: 'V-4295'
  tag rid: 'SV-4295r2_rule'
  tag stig_id: 'GEN005500'
  tag gtitle: 'GEN005500'
  tag fix_id: 'F-4206r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCPP-1'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
