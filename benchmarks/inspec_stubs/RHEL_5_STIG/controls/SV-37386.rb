control 'SV-37386' do
  title 'The /etc/gshadow file must not contain any group password hashes.'
  desc 'Group passwords are typically shared and should not be used.'
  desc 'fix', 'Edit /etc/gshadow and change the password field to an exclamation point (!) to lock the group password.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22349'
  tag rid: 'SV-37386r1_rule'
  tag stig_id: 'GEN000000-LNX001476'
  tag gtitle: 'GEN000000-LNX001476'
  tag fix_id: 'F-31317r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
