control 'SV-1054' do
  title 'The /etc/access.conf file must have a privileged group owner.'
  desc 'Depending on the access restrictions of the /etc/access.conf file, if the group owner were not a privileged group, it could endanger system security.'
  desc 'check', 'Check access configuration group ownership:

# ls -lL /etc/login.access /etc/security/access.conf /etc/access.conf

If any of these files exist and are have a group-owner that is not a privileged user, this is a finding.'
  desc 'fix', 'Use the chgrp command to ensure the group owner is root, sys, or bin.
For example:
# chgrp root /etc/login.access /etc/security/access.conf /etc/access.conf'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-28799r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1054'
  tag rid: 'SV-1054r2_rule'
  tag stig_id: 'GEN000000-LNX00420'
  tag gtitle: 'GEN000000-LNX00420'
  tag fix_id: 'F-1208r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
