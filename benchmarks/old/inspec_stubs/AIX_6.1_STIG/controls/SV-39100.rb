control 'SV-39100' do
  title 'The /etc/hosts file must be group-owned by bin, sys, or system.'
  desc 'The /etc/hosts file (or equivalent) configures local host name to IP address mappings that typically take precedence over DNS resolution.  If this file is maliciously modified, it could cause the failure or compromise of security functions requiring name resolution, which may include time synchronization, centralized authentication, and remote system logging.'
  desc 'check', "Check the /etc/hosts file's group ownership.

Procedure:
# ls -lL /etc/hosts

If the file is not group-owned by bin, sys, or system, this is a finding."
  desc 'fix', 'Change the group owner of the /etc/hosts file to sys, bin, or system.

Procedure:
# chgrp system /etc/hosts'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-38081r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22324'
  tag rid: 'SV-39100r1_rule'
  tag stig_id: 'GEN001367'
  tag gtitle: 'GEN001367'
  tag fix_id: 'F-33351r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
