control 'SV-217871' do
  title 'The /etc/shadow file must be owned by root.'
  desc 'The "/etc/shadow" file contains the list of local system accounts and stores password hashes. Protection of this file is critical for system security. Failure to give ownership of this file to root provides the designated owner with access to sensitive information which could weaken the system security posture.'
  desc 'check', 'To check the ownership of "/etc/shadow", run the command: 

$ ls -l /etc/shadow

If properly configured, the output should indicate the following owner: "root" 
If it does not, this is a finding.'
  desc 'fix', 'To properly set the owner of "/etc/shadow", run the command: 

# chown root /etc/shadow'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19352r376628_chk'
  tag severity: 'medium'
  tag gid: 'V-217871'
  tag rid: 'SV-217871r603264_rule'
  tag stig_id: 'RHEL-06-000033'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-19350r376629_fix'
  tag 'documentable'
  tag legacy: ['V-38502', 'SV-50303']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
