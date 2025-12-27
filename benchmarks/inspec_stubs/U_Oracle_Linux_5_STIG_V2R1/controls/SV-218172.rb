control 'SV-218172' do
  title 'The /etc/security/access.conf file must have a privileged group owner.'
  desc 'Depending on the access restrictions of the /etc/security/access.conf file, if the group owner were not a privileged group, it could endanger system security.'
  desc 'check', 'Check access configuration group ownership:

# ls -lL /etc/security/access.conf

If this file exists and has a group-owner that is not a privileged user, this is a finding.'
  desc 'fix', 'Use the chgrp command to ensure the group owner is root, sys, or bin.
(for example:
# chgrp root /etc/security/access.conf

).'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19647r553853_chk'
  tag severity: 'medium'
  tag gid: 'V-218172'
  tag rid: 'SV-218172r603259_rule'
  tag stig_id: 'GEN000000-LNX00420'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19645r553854_fix'
  tag 'documentable'
  tag legacy: ['V-1054', 'SV-62901']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
