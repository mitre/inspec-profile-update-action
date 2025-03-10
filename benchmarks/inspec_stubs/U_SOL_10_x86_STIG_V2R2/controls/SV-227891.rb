control 'SV-227891' do
  title 'The SSH client must be configured to only use the SSHv2 protocol.'
  desc 'SSHv1 is not a DoD-approved protocol and has many well-known vulnerability exploits.  Exploits of the SSH client could provide access to the system with the privileges of the user running the client.'
  desc 'check', "Check the SSH client configuration for allowed protocol versions.
# grep -i protocol /etc/ssh/ssh_config | grep -v '^#' 
If the returned protocol configuration allows versions less than 2, this is a finding."
  desc 'fix', 'Edit the /etc/ssh/ssh_config file and add or edit a Protocol configuration line that does not allow versions less than 2.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30053r490078_chk'
  tag severity: 'medium'
  tag gid: 'V-227891'
  tag rid: 'SV-227891r603266_rule'
  tag stig_id: 'GEN005501'
  tag gtitle: 'SRG-OS-000074'
  tag fix_id: 'F-30041r490079_fix'
  tag 'documentable'
  tag legacy: ['V-22456', 'SV-26749']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
