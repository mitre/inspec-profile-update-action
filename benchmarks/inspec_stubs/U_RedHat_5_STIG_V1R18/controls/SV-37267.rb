control 'SV-37267' do
  title 'NIS/NIS+/yp files must be owned by root, sys, or bin.'
  desc "NIS/NIS+/yp files are part of the system's identification and authentication processes and are critical to system security.  Failure to give ownership of sensitive files or utilities to root or bin provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Perform the following to check NIS file ownership:
# ls -la /var/yp/*;
If the file ownership is not root, sys, or bin, this is a finding.'
  desc 'fix', 'Change the ownership of NIS/NIS+/yp files to root, sys or bin. 

Procedure (example):
# chown root <filename>'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-35953r1_chk'
  tag severity: 'medium'
  tag gid: 'V-789'
  tag rid: 'SV-37267r1_rule'
  tag stig_id: 'GEN001320'
  tag gtitle: 'GEN001320'
  tag fix_id: 'F-31213r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
