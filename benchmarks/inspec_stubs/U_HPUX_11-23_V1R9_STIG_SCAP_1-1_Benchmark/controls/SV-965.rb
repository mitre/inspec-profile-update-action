control 'SV-965' do
  title 'The HP-UX /etc/securetty must be group-owned by root, sys, or bin.'
  desc 'Root, sys, and bin are the most privileged group accounts, by default, for most UNIX systems.  If a file as sensitive as /etc/securetty is not group-owned by a privileged group, it could lead to system compromise.'
  desc 'fix', 'Change the group-owner of the /etc/securetty to root, bin, or sys.
Example:
# chgrp root /etc/securetty'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-965'
  tag rid: 'SV-965r2_rule'
  tag stig_id: 'GEN000000-HPUX0080'
  tag gtitle: 'GEN000000-HPUX0080'
  tag fix_id: 'F-1119r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
