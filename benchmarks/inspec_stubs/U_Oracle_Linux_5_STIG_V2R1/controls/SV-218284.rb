control 'SV-218284' do
  title 'The /etc/hosts file must be group-owned by root, bin, or sys.'
  desc 'The /etc/hosts file (or equivalent) configures local host name to IP address mappings that typically take precedence over DNS resolution.  If this file is maliciously modified, it could cause the failure or compromise of security functions requiring name resolution, which may include time synchronization, centralized authentication, and remote system logging.'
  desc 'check', "Check the /etc/hosts file's group ownership.

Procedure:
# ls -lL /etc/hosts

If the file is not group-owned by root, bin, or sys, this is a finding."
  desc 'fix', 'Change the group-owner of the /etc/hosts file to root, sys, or bin.

Procedure:
# chgrp root /etc/hosts'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19759r568810_chk'
  tag severity: 'medium'
  tag gid: 'V-218284'
  tag rid: 'SV-218284r603259_rule'
  tag stig_id: 'GEN001367'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19757r568811_fix'
  tag 'documentable'
  tag legacy: ['V-22324', 'SV-64523']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
