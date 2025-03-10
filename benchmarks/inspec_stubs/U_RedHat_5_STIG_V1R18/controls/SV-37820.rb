control 'SV-37820' do
  title 'The SSH client must be configured to only use the SSHv2 protocol.'
  desc 'SSHv1 is not a DoD-approved protocol and has many well-known vulnerability exploits.  Exploits of the SSH client could provide access to the system with the privileges of the user running the client.'
  desc 'check', "Check the SSH client configuration for allowed protocol versions.
# grep -i protocol /etc/ssh/ssh_config | grep -v '^#' 
If the returned protocol configuration allows versions less than 2, this is a finding."
  desc 'fix', 'Edit the /etc/ssh/ssh_config file and add or edit a "Protocol" configuration line not allowing versions less than 2.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-37022r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22456'
  tag rid: 'SV-37820r1_rule'
  tag stig_id: 'GEN005501'
  tag gtitle: 'GEN005501'
  tag fix_id: 'F-32289r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCPP-1'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
