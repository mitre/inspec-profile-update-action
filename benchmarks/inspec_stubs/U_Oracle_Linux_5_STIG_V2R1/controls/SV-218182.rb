control 'SV-218182' do
  title 'The /etc/securetty file must be group-owned by root, sys, or bin.'
  desc 'The securetty file contains the list of terminals permitting direct root logins.  It must be protected from unauthorized modification.'
  desc 'check', 'Check /etc/securetty group ownership:

# ls -lL /etc/securetty

If /etc/securetty is not group owned by root, sys, or bin, then this is a finding.'
  desc 'fix', 'Change the group-owner of /etc/securetty to root, sys, or bin.
Example:
# chgrp root /etc/securetty'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19657r561473_chk'
  tag severity: 'medium'
  tag gid: 'V-218182'
  tag rid: 'SV-218182r603259_rule'
  tag stig_id: 'GEN000000-LNX00620'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19655r561474_fix'
  tag 'documentable'
  tag legacy: ['V-12038', 'SV-63013']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
