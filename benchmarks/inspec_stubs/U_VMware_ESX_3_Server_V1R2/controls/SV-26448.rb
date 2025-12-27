control 'SV-26448' do
  title 'The /etc/gshadow file must not contain any group password hashes.'
  desc 'Group passwords are typically shared and should not be used.'
  desc 'check', "Check the /etc/gshadow file for password hashes.
# cut -d : -f 2 /etc/gshadow | egrep -v '^(x|!|)$'
If any password hashes are returned, this is a finding."
  desc 'fix', 'Edit /etc/gshadow and change the password field to an exclamation point (!) to lock the group password.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27520r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22349'
  tag rid: 'SV-26448r1_rule'
  tag stig_id: 'GEN001476'
  tag gtitle: 'GEN000000-LNX001476'
  tag fix_id: 'F-23640r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
