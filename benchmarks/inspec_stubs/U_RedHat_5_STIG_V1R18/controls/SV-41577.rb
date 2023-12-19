control 'SV-41577' do
  title 'NIS/NIS+/yp files must be group-owned by root, sys, or bin.'
  desc "NIS/NIS+/yp files are part of the system's identification and authentication processes and are, therefore, critical to system security.  Failure to give ownership of sensitive files or utilities to root or bin provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Perform the following to check NIS file group ownership:

# ls -la /var/yp/*

If the file group ownership is not root, sys, or bin, this is a finding.'
  desc 'fix', 'Perform the following to change NIS file ownership.

# chgrp root /var/yp/*'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-40079r2_chk'
  tag severity: 'medium'
  tag gid: 'V-790'
  tag rid: 'SV-41577r2_rule'
  tag stig_id: 'GEN001340'
  tag gtitle: 'GEN001340'
  tag fix_id: 'F-35235r4_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
