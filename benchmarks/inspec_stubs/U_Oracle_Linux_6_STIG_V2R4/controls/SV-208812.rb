control 'SV-208812' do
  title 'The /etc/shadow file must have mode 0000.'
  desc 'The "/etc/shadow" file contains the list of local system accounts and stores password hashes. Protection of this file is critical for system security. Failure to give ownership of this file to root provides the designated owner with access to sensitive information which could weaken the system security posture.'
  desc 'check', 'To check the permissions of "/etc/shadow", run the command: 

$ ls -l /etc/shadow

If properly configured, the output should indicate the following permissions: "----------" 
If it does not, this is a finding.'
  desc 'fix', 'To properly set the permissions of "/etc/shadow", run the command: 

# chmod 0000 /etc/shadow'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9065r357416_chk'
  tag severity: 'medium'
  tag gid: 'V-208812'
  tag rid: 'SV-208812r603263_rule'
  tag stig_id: 'OL6-00-000035'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9065r357417_fix'
  tag 'documentable'
  tag legacy: ['V-50757', 'SV-64963']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
