control 'SV-38776' do
  title 'NIS/NIS+/yp files must be group-owned by sys, bin, other, or system.'
  desc "NIS/NIS+/yp files are part of the system's identification and authentication processes and are, therefore, critical to system security.  Failure to give ownership of sensitive files or utilities to root or bin provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check the group ownership of the NIS files.

Procedure:
# ls -lRa /var/nis /var/yp /usr/lib/nis /usr/lib/netsvc/yp

If the file group owner is not sys, bin, or system, this is a finding.'
  desc 'fix', 'Change the group owner of the NIS files to sys, bin, system, or other. 
Procedure:
 # chgrp system < directory>/< file >'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-36964r1_chk'
  tag severity: 'medium'
  tag gid: 'V-790'
  tag rid: 'SV-38776r1_rule'
  tag stig_id: 'GEN001340'
  tag gtitle: 'GEN001340'
  tag fix_id: 'F-33349r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
