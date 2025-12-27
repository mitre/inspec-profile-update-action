control 'SV-226455' do
  title 'Users must not be able to change passwords more than once every 24 hours.'
  desc 'The ability to change passwords frequently facilitates users reusing the same password. This can result in users effectively never changing their passwords. This would be accomplished by users changing their passwords when required and then immediately changing it to the original value.'
  desc 'check', "Check the minimum time period between password changes for each user account is 1 day or greater.
# awk -F: '$4 < 1 {print $1}' /etc/shadow
If any results are returned that are not associated with a system account, this is a finding."
  desc 'fix', 'Edit the /etc/default/passwd file and set the variable "MINWEEKS" to 1 or greater. 
Set the per-user minimum password change times by using the following command on each user account.
# passwd -n <number of days> <accountname>'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28616r482741_chk'
  tag severity: 'medium'
  tag gid: 'V-226455'
  tag rid: 'SV-226455r603265_rule'
  tag stig_id: 'GEN000540'
  tag gtitle: 'SRG-OS-000075'
  tag fix_id: 'F-28604r482742_fix'
  tag 'documentable'
  tag legacy: ['SV-39809', 'V-1032']
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
