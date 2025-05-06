control 'SV-226507' do
  title 'The /etc/hosts file must be group-owned by root, bin, or sys.'
  desc 'The /etc/hosts file (or equivalent) configures local host name to IP address mappings that typically take precedence over DNS resolution.  If this file is maliciously modified, it could cause the failure or compromise of security functions requiring name resolution, which may include time synchronization, centralized authentication, and remote system logging.'
  desc 'check', "Check the /etc/hosts file's group ownership.

Procedure:
# ls -lL /etc/hosts

If the file is not group-owned by root, bin, or sys, this is a finding."
  desc 'fix', 'Change the group owner of the /etc/hosts file to root, sys, or bin.

Procedure:
# chgrp root /etc/hosts'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28668r482909_chk'
  tag severity: 'medium'
  tag gid: 'V-226507'
  tag rid: 'SV-226507r603265_rule'
  tag stig_id: 'GEN001367'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28656r482910_fix'
  tag 'documentable'
  tag legacy: ['SV-39896', 'V-22324']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
