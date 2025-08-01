control 'SV-218288' do
  title 'The /etc/nsswitch.conf file must be group-owned by root, bin, or sys.'
  desc 'The nsswitch.conf file (or equivalent) configures the source of a variety of system security information including account, group, and host lookups.  Malicious changes could prevent the system from functioning or compromise system security.'
  desc 'check', 'Check the group ownership of the nsswitch.conf file.

Procedure:
# ls -lL /etc/nsswitch.conf

If the file is not group-owned by root, bin or sys, this is a finding.'
  desc 'fix', 'Change the group-owner of the /etc/nsswitch.conf file to root, bin or sys.

Procedure:
# chgrp root /etc/nsswitch.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19763r561653_chk'
  tag severity: 'medium'
  tag gid: 'V-218288'
  tag rid: 'SV-218288r603259_rule'
  tag stig_id: 'GEN001372'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19761r561654_fix'
  tag 'documentable'
  tag legacy: ['V-22328', 'SV-64539']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
