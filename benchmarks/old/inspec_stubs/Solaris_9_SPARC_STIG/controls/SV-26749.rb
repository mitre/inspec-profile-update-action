control 'SV-26749' do
  title 'The SSH client must be configured to only use the SSHv2 protocol.'
  desc 'SSHv1 is not a DoD-approved protocol and has many well-known vulnerability exploits.  Exploits of the SSH client could provide access to the system with the privileges of the user running the client.'
  desc 'fix', 'Edit the /etc/ssh/ssh_config file and add or edit a Protocol configuration line that does not allow versions less than 2.'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-22456'
  tag rid: 'SV-26749r1_rule'
  tag stig_id: 'GEN005501'
  tag gtitle: 'GEN005501'
  tag fix_id: 'F-23999r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCPP-1'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
