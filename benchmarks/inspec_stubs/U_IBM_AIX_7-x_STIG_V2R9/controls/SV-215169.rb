control 'SV-215169' do
  title 'AIX /etc/security/mkuser.sys.custom file must not exist unless it is needed for customizing a new user account.'
  desc 'The "/etc/security/mkuser.sys.custom" is called by "/etc/security/mkuser.sys" to customize the new user account when a new user is created, or a user is logging into the system without a home directory. An improper "/etc/security/mkuser.sys.custom" script increases the risk that non-privileged users may obtain elevated privileges. It must not exist unless it is needed.'
  desc 'check', 'Check if the "/etc/security/mkuser.sys.custom" file exists:
# ls /etc/security/mkuser.sys.custom

If the above command shows the file exists, this is a finding.'
  desc 'fix', 'Remove the "/etc/security/mkuser.sys.custom" file using the following command:

# rm /etc/security/mkuser.sys.custom'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16367r293958_chk'
  tag severity: 'medium'
  tag gid: 'V-215169'
  tag rid: 'SV-215169r508663_rule'
  tag stig_id: 'AIX7-00-001000'
  tag gtitle: 'SRG-OS-000001-GPOS-00001'
  tag fix_id: 'F-16365r293959_fix'
  tag 'documentable'
  tag legacy: ['SV-101313', 'V-91213']
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
