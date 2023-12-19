control 'SV-218276' do
  title 'NIS/NIS+/yp files must be group-owned by root, sys, or bin.'
  desc "NIS/NIS+/yp files are part of the system's identification and authentication processes and are, therefore, critical to system security.  Failure to give ownership of sensitive files or utilities to root or bin provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Perform the following to check NIS file group ownership:

# ls -la /var/yp/*

If the file group ownership is not root, sys, or bin, this is a finding.'
  desc 'fix', 'Perform the following to change NIS file ownership.

# chgrp root /var/yp/*'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19751r561437_chk'
  tag severity: 'medium'
  tag gid: 'V-218276'
  tag rid: 'SV-218276r603259_rule'
  tag stig_id: 'GEN001340'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19749r561438_fix'
  tag 'documentable'
  tag legacy: ['V-790', 'SV-64515']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
