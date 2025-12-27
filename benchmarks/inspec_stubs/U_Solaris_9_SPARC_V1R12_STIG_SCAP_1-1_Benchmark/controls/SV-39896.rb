control 'SV-39896' do
  title 'The /etc/hosts file must be group-owned by root, bin, or sys.'
  desc 'The /etc/hosts file (or equivalent) configures local host name to IP address mappings that typically take precedence over DNS resolution.  If this file is maliciously modified, it could cause the failure or compromise of security functions requiring name resolution, which may include time synchronization, centralized authentication, and remote system logging.'
  desc 'fix', 'Change the group owner of the /etc/hosts file to root, sys, or bin.

Procedure:
# chgrp root /etc/hosts'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-22324'
  tag rid: 'SV-39896r1_rule'
  tag stig_id: 'GEN001367'
  tag gtitle: 'GEN001367'
  tag fix_id: 'F-34053r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
