control 'SV-26349' do
  title 'The system must restrict the ability to switch to the root user to members of a defined group.'
  desc 'Configuring a supplemental group for users permitted to switch to the root user prevents unauthorized users from accessing the root account, even with knowledge of the root credentials.'
  desc 'check', 'Check /etc/default/security for the SU_ROOT_GROUP setting.

# grep SU_ROOT_GROUP /etc/default/security

Unless this setting is present, configured, and not commented out, this is a finding.'
  desc 'fix', 'Edit /etc/default/security and uncomment, set, or add the SU_ROOT_GROUP setting with a value of wheel or equivalent. If necessary, create a wheel group and add administrative users to the group.'
  impact 0.3
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36297r1_chk'
  tag severity: 'low'
  tag gid: 'V-22308'
  tag rid: 'SV-26349r1_rule'
  tag stig_id: 'GEN000850'
  tag gtitle: 'GEN000850'
  tag fix_id: 'F-31552r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000009']
  tag nist: ['AC-2 c']
end
