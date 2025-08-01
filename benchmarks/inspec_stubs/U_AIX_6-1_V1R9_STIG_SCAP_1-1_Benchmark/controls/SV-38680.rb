control 'SV-38680' do
  title 'The system must restrict the ability to switch to the root user to members of a defined group.'
  desc 'Configuring a supplemental group for users permitted to switch to the root user prevents unauthorized users from accessing the root account, even with knowledge of the root credentials.'
  desc 'fix', 'Use the chsec command to only allow users in the adm group to su to root.
#chsec -f /etc/security/user -s root -a sugroups=adm'
  impact 0.3
  ref 'DPMS Target AIX 6.1'
  tag severity: 'low'
  tag gid: 'V-22308'
  tag rid: 'SV-38680r1_rule'
  tag stig_id: 'GEN000850'
  tag gtitle: 'GEN000850'
  tag fix_id: 'F-32099r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000009']
  tag nist: ['AC-2 c']
end
