control 'SV-26348' do
  title 'The system must restrict the ability to switch to the root user for members of a defined group.'
  desc 'Configuring a supplemental group for users permitted to switch to the root user prevents unauthorized users from accessing the root account, even with knowledge of the root credentials.'
  desc 'check', 'Consult vendor documentation to determine if a specific configuration setting is available to restrict the ability to switch to the root user.  If there is, and this is not configured, this is a finding.

If there is not specific configuration, verify su is group-owned by the group permitted to access root and has no other execute permission.

Procedure:
# ls -l /bin/su

If the group owner is not the group permitted access to root, or if /bin/su is executable by other users, this is a finding.'
  desc 'fix', 'If the OS has a specific configuration setting to restrict access to root to a particular group, configure this in accordance with vendor documentation.

Otherwise, change the group ownership of su to the group permitted root access, and remove any other execute permission.

Procedure:
# chgrp <authorized group> /bin/su
# chmod o-x /bin/su'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27455r1_chk'
  tag severity: 'low'
  tag gid: 'V-22308'
  tag rid: 'SV-26348r1_rule'
  tag stig_id: 'GEN000850'
  tag gtitle: 'GEN000850'
  tag fix_id: 'F-23524r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000009']
  tag nist: ['AC-2 c']
end
