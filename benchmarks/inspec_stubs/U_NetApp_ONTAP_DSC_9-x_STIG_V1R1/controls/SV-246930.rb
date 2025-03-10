control 'SV-246930' do
  title 'ONTAP must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.'
  desc 'Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.

Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals that do not possess appropriate authorizations.'
  desc 'check', 'Use "security login role show” to see role-based access policies defined in ONTAP for privileged and unprivileged users. Privileged users have the role of admin.

If ONTAP does not prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures, this is a finding.'
  desc 'fix', 'Configure privileged users with "security login create -user-or-group-name <user_name> -role admin".

Configure non-privileged users with "security login create -user-or-group-name <user_name> -role <role_name>“where a non-privileged user role other than admin is used.'
  impact 0.7
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50362r769120_chk'
  tag severity: 'high'
  tag gid: 'V-246930'
  tag rid: 'SV-246930r769122_rule'
  tag stig_id: 'NAOT-AC-000009'
  tag gtitle: 'SRG-APP-000340-NDM-000288'
  tag fix_id: 'F-50316r769121_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
