control 'SV-46084' do
  title 'The system package management tool must not automatically obtain updates.'
  desc "System package management tools can obtain a list of updates and patches from a package repository and make this information available to the SA for review and action. Using a package repository outside of the organization's control presents a risk of malicious packages being introduced."
  desc 'check', 'Check for the existence of a cron job called opensuse.org-online_update
# find /etc/cron* -name opensuse*
If a symlink or executable script is found, this is a finding.'
  desc 'fix', 'Disable the Automatic Online Update option using YaST.
# /sbin/yast2 online_update_configuration
Uncheck the “Automatic Online Update” selection.
Select “Finish” to exit  
If /etc/<cron directory>/opensuse.org-online_update still exists, remove it manually
rm /etc/<cron directory>/opensuse.org-online_update'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43341r1_chk'
  tag severity: 'low'
  tag gid: 'V-22589'
  tag rid: 'SV-46084r1_rule'
  tag stig_id: 'GEN008820'
  tag gtitle: 'GEN008820'
  tag fix_id: 'F-39429r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001233']
  tag nist: ['SI-2 (2)']
end
