control 'SV-39903' do
  title 'The services file must be group-owned by root, bin, or sys.'
  desc "Failure to give ownership of system configuration files to root or a system group provides the designated owner and unauthorized users with the potential to change the system configuration which could weaken the system's security posture."
  desc 'fix', 'Change the group-owner of the services file.

Procedure:
# chgrp root /etc/services'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-22427'
  tag rid: 'SV-39903r1_rule'
  tag stig_id: 'GEN003770'
  tag gtitle: 'GEN003770'
  tag fix_id: 'F-34062r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
