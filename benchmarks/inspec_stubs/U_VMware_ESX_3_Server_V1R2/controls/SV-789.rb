control 'SV-789' do
  title 'NIS/NIS+/yp files must be owned by root, sys, or bin.'
  desc "NIS/NIS+/yp files are part of the system's identification and authentication processes and are, therefore, critical to system security.  Failure to give ownership of sensitive files or utilities to root or bin provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check the ownership of NIS/NIS+/yp files.  Consult vendor documentation to determine the location of these files on the system.

Procedure (example):
# ls -lL /path/to/file

If such a file is not owned by root, sys, bin, or system, this is a finding.'
  desc 'fix', 'Change the ownership of NIS/NIS+/yp files to root, sys, bin, or system.  Consult vendor documentation to determine the location of the files.

Procedure (example):
# chown root <filename>'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-294r2_chk'
  tag severity: 'medium'
  tag gid: 'V-789'
  tag rid: 'SV-789r2_rule'
  tag stig_id: 'GEN001320'
  tag gtitle: 'GEN001320'
  tag fix_id: 'F-943r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
