control 'SV-37330' do
  title 'The /etc/nsswitch.conf file must be group-owned by root, bin, or sys.'
  desc 'The nsswitch.conf file (or equivalent) configures the source of a variety of system security information including account, group, and host lookups.  Malicious changes could prevent the system from functioning or compromise system security.'
  desc 'fix', 'Change the group-owner of the /etc/nsswitch.conf file to root, bin or sys.

Procedure:
# chgrp root /etc/nsswitch.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22328'
  tag rid: 'SV-37330r1_rule'
  tag stig_id: 'GEN001372'
  tag gtitle: 'GEN001372'
  tag fix_id: 'F-31268r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
