control 'SV-39209' do
  title 'The SSH client must be configured to only use the SSHv2 protocol.'
  desc 'SSHv1 is not a DoD-approved protocol and has many well-known vulnerability exploits.  Exploits of the SSH client could provide access to the system with the privileges of the user running the client.'
  desc 'check', "Check the SSH client configuration for allowed protocol versions. 

# grep -i protocol /etc/ssh/ssh_config | grep -v '^#' 

If the variables Protocol 2,1 or Protocol 1 are defined on a line without a leading comment, this is a finding. 

If the SSH client is F-Secure, the variable name for SSH 1 compatibility is Ssh1Compatibility, not protocol. If the variable Ssh1Compatiblity is set to yes, this is a finding."
  desc 'fix', 'Edit the /etc/ssh/ssh_config file and add or edit a Protocol configuration line that does not allow versions less than 2.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-38187r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22456'
  tag rid: 'SV-39209r1_rule'
  tag stig_id: 'GEN005501'
  tag gtitle: 'GEN005501'
  tag fix_id: 'F-33461r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCPP-1'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
