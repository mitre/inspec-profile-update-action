control 'SV-218225' do
  title 'Users must not be able to change passwords more than once every 24 hours.'
  desc 'The ability to change passwords frequently facilitates users reusing the same password. This can result in users effectively never changing their passwords.  This would be accomplished by users changing their passwords when required and then immediately changing it to the original value.'
  desc 'check', "Check the minimum time period between password changes for each user account is 1 day.
# cat /etc/shadow | cut -d ':' -f 4 | grep -v 1
If any results are returned, this is a finding."
  desc 'fix', 'Change the minimum time period between password changes for each user account to 1 day.

# passwd -n 1 <user name>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19700r568576_chk'
  tag severity: 'medium'
  tag gid: 'V-218225'
  tag rid: 'SV-218225r603259_rule'
  tag stig_id: 'GEN000540'
  tag gtitle: 'SRG-OS-000075-GPOS-00043'
  tag fix_id: 'F-19698r568577_fix'
  tag 'documentable'
  tag legacy: ['V-1032', 'SV-63659']
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
