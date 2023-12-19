control 'SV-39101' do
  title 'The /etc/nsswitch.conf file must be group-owned by root, bin, sys, or system.'
  desc 'The nsswitch.conf file (or equivalent) configures the source of a variety of system security information including account, group, and host lookups.  Malicious changes could prevent the system from functioning or compromise system security.'
  desc 'check', 'Check the group ownership of the nsswitch.conf file.

AIX does not use the /etc/nsswitch.conf file.  This check is not applicable.

Procedure:
# ls -lL /etc/nsswitch.conf

If the file is not group-owned by root, bin, sys, or system, this is a finding.'
  desc 'fix', 'Change the group owner of the /etc/nsswitch.conf file to root, bin, sys, or system.

Procedure:
# chgrp system /etc/nsswitch.conf'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-38082r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22328'
  tag rid: 'SV-39101r1_rule'
  tag stig_id: 'GEN001372'
  tag gtitle: 'GEN001372'
  tag fix_id: 'F-33352r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
