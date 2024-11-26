control 'SV-37340' do
  title 'The /etc/securetty file must be group-owned by root, sys, or bin.'
  desc 'The securetty file contains the list of terminals permitting direct root logins.  It must be protected from unauthorized modification.'
  desc 'check', 'Check /etc/securetty group ownership:

# ls -lL /etc/securetty

If /etc/securetty is not group owned by root, sys, or bin, then this is a finding.'
  desc 'fix', 'Change the group-owner of /etc/securetty to root, sys, or bin.
Example:
# chgrp root /etc/securetty'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-8001r2_chk'
  tag severity: 'medium'
  tag gid: 'V-12038'
  tag rid: 'SV-37340r1_rule'
  tag stig_id: 'GEN000000-LNX00620'
  tag gtitle: 'GEN000000-LNX00620'
  tag fix_id: 'F-11295r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
