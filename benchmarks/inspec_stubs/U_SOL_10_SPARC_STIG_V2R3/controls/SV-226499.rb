control 'SV-226499' do
  title 'NIS/NIS+/yp files must be group-owned by root, sys, or bin.'
  desc "NIS/NIS+/yp files are part of the system's identification and authentication processes and are, therefore, critical to system security.  Failure to give ownership of sensitive files or utilities to root or bin provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Perform the following to check NIS file ownership.
# ls -lRa /usr/lib/netsvc/yp /var/yp
If the file group owner is not root, sys, or bin, this is a finding.'
  desc 'fix', 'Change the group owner of the NIS files to root, bin, or sys.

Procedure:
# chgrp -R root /usr/lib/netsvc/yp /var/yp'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28660r482885_chk'
  tag severity: 'medium'
  tag gid: 'V-226499'
  tag rid: 'SV-226499r854410_rule'
  tag stig_id: 'GEN001340'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-28648r482886_fix'
  tag 'documentable'
  tag legacy: ['V-790', 'SV-27171']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
