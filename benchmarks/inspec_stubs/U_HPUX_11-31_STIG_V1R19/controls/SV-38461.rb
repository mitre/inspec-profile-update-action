control 'SV-38461' do
  title 'NIS/NIS+/yp files must be group-owned by root, sys, bin, or other.'
  desc "NIS/NIS+/yp files are part of the system's identification and authentication processes and are, therefore, critical to system security.  Failure to give ownership of sensitive files or utilities to root or bin provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check NIS file ownership.
# ls -alLR /var/yp/`domainname`

If the file group owner is not root, sys, bin (the default), or other, this is a finding.'
  desc 'fix', 'Change the group owner of the NIS files to root, sys, bin, or other. 
# chgrp root <filename>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36304r3_chk'
  tag severity: 'medium'
  tag gid: 'V-790'
  tag rid: 'SV-38461r1_rule'
  tag stig_id: 'GEN001340'
  tag gtitle: 'GEN001340'
  tag fix_id: 'F-31559r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
