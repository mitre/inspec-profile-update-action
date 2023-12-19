control 'SV-38775' do
  title 'NIS/NIS+/yp files must be owned by root, sys, or bin.'
  desc "NIS/NIS+/yp files are part of the system's identification and authentication processes and are, therefore, critical to system security.  Failure to give ownership of sensitive files or utilities to root or bin provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Perform the following to check NIS file ownership.
# ls -lRa /var/nis /var/yp /usr/lib/nis /usr/lib/netsvc/yp
If the file ownership is not root, sys, or bin, this is a finding.'
  desc 'fix', 'Change the owner of the NIS files to root, sys, or bin.
Procedure (example):
# chown root < directory>/< file >'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-36963r1_chk'
  tag severity: 'medium'
  tag gid: 'V-789'
  tag rid: 'SV-38775r1_rule'
  tag stig_id: 'GEN001320'
  tag gtitle: 'GEN001320'
  tag fix_id: 'F-35060r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
