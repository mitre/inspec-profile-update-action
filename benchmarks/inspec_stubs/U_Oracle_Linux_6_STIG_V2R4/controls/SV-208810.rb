control 'SV-208810' do
  title 'The /etc/shadow file must be owned by root.'
  desc 'The "/etc/shadow" file contains the list of local system accounts and stores password hashes. Protection of this file is critical for system security. Failure to give ownership of this file to root provides the designated owner with access to sensitive information which could weaken the system security posture.'
  desc 'check', 'To check the ownership of "/etc/shadow", run the command: 

$ ls -l /etc/shadow

If properly configured, the output should indicate the following owner: "root" 
If it does not, this is a finding.'
  desc 'fix', 'To properly set the owner of "/etc/shadow", run the command: 

# chown root /etc/shadow'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9063r357410_chk'
  tag severity: 'medium'
  tag gid: 'V-208810'
  tag rid: 'SV-208810r603263_rule'
  tag stig_id: 'OL6-00-000033'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9063r357411_fix'
  tag 'documentable'
  tag legacy: ['SV-64959', 'V-50753']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
