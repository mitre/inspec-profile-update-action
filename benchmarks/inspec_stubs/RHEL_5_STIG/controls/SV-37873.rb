control 'SV-37873' do
  title 'The /etc/smb.conf file must be group-owned by root, bin, sys, or system.'
  desc 'If the group owner of the "smb.conf" file is not root or a system group, the file may be maliciously modified and the Samba configuration could be compromised.'
  desc 'fix', 'Change the group owner of the smb.conf file.

Procedure:
# chgrp root smb.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-1056'
  tag rid: 'SV-37873r1_rule'
  tag stig_id: 'GEN006120'
  tag gtitle: 'GEN006120'
  tag fix_id: 'F-32365r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
