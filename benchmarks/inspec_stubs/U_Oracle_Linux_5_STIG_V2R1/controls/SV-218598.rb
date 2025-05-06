control 'SV-218598' do
  title 'The SSH client must be configured to only use the SSHv2 protocol.'
  desc 'SSHv1 is not a DoD-approved protocol and has many well-known vulnerability exploits.  Exploits of the SSH client could provide access to the system with the privileges of the user running the client.'
  desc 'check', "Check the SSH client configuration for allowed protocol versions.
# grep -i protocol /etc/ssh/ssh_config | grep -v '^#' 
If the returned protocol configuration allows versions less than 2, this is a finding."
  desc 'fix', 'Edit the /etc/ssh/ssh_config file and add or edit a "Protocol" configuration line not allowing versions less than 2.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20073r562831_chk'
  tag severity: 'medium'
  tag gid: 'V-218598'
  tag rid: 'SV-218598r603259_rule'
  tag stig_id: 'GEN005501'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag fix_id: 'F-20071r562832_fix'
  tag 'documentable'
  tag legacy: ['V-22456', 'SV-63547']
  tag cci: ['CCI-000197', 'CCI-001436']
  tag nist: ['IA-5 (1) (c)', 'AC-17 (8)']
end
