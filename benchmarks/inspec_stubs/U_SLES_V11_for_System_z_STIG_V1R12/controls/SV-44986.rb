control 'SV-44986' do
  title 'The /etc/nsswitch.conf file must be group-owned by root, bin, sys or system.'
  desc 'The nsswitch.conf file (or equivalent) configures the source of a variety of system security information including account, group, and host lookups.  Malicious changes could prevent the system from functioning or compromise system security.'
  desc 'check', 'Check the group ownership of the nsswitch.conf file.

Procedure:
# ls -lL /etc/nsswitch.conf

If the file is not group-owned by root, bin, sys, or system, this is a finding.'
  desc 'fix', 'Change the group-owner of the /etc/nsswitch.conf file to root, bin, sys, or system.

Procedure:
# chgrp root /etc/nsswitch.conf'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42393r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22328'
  tag rid: 'SV-44986r1_rule'
  tag stig_id: 'GEN001372'
  tag gtitle: 'GEN001372'
  tag fix_id: 'F-38403r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
