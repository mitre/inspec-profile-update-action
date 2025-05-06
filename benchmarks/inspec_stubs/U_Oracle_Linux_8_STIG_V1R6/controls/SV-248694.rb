control 'SV-248694' do
  title 'OL 8 passwords for new users or password changes must have a 24 hours/1 day minimum password lifetime restriction in "/etc/shadow".'
  desc "Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse."
  desc 'check', %q(Verify the minimum time period between password changes for each user account is one day or greater. 
 
$ sudo awk -F: '$4 < 1 {print $1 " " $4}' /etc/shadow 
 
If any results are returned that are not associated with a system account, this is a finding.)
  desc 'fix', 'Configure non-compliant accounts to enforce a 24 hours/1 day minimum password lifetime: 
 
$ sudo chage -m 1 [user]'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52128r779646_chk'
  tag severity: 'medium'
  tag gid: 'V-248694'
  tag rid: 'SV-248694r779648_rule'
  tag stig_id: 'OL08-00-020180'
  tag gtitle: 'SRG-OS-000075-GPOS-00043'
  tag fix_id: 'F-52082r779647_fix'
  tag 'documentable'
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
