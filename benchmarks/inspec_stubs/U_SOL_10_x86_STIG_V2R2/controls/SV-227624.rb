control 'SV-227624' do
  title 'NIS/NIS+/yp files must be owned by root, sys, or bin.'
  desc "NIS/NIS+/yp files are part of the system's identification and authentication processes and are, therefore, critical to system security.  Failure to give ownership of sensitive files or utilities to root or bin provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Perform the following to check NIS file ownership.
# ls -lRa /usr/lib/netsvc/yp /var/yp
If the file ownership is not root, sys, or bin, this is a finding.'
  desc 'fix', 'Change the ownership of NIS/NIS+/yp files to root, bin, or sys.

Procedure:
# chown -R root /usr/lib/netsvc/yp /var/yp'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29786r488432_chk'
  tag severity: 'medium'
  tag gid: 'V-227624'
  tag rid: 'SV-227624r603266_rule'
  tag stig_id: 'GEN001320'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-29774r488433_fix'
  tag 'documentable'
  tag legacy: ['V-789', 'SV-27166']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
