control 'SV-27171' do
  title 'NIS/NIS+/yp files must be group-owned by root, sys, or bin.'
  desc "NIS/NIS+/yp files are part of the system's identification and authentication processes and are, therefore, critical to system security.  Failure to give ownership of sensitive files or utilities to root or bin provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'fix', 'Change the group owner of the NIS files to root, bin, or sys.

Procedure:
# chgrp -R root /usr/lib/netsvc/yp /var/yp'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-790'
  tag rid: 'SV-27171r1_rule'
  tag stig_id: 'GEN001340'
  tag gtitle: 'GEN001340'
  tag fix_id: 'F-34043r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
