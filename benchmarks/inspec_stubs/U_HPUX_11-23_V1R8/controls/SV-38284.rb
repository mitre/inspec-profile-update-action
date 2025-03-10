control 'SV-38284' do
  title 'NIS/NIS+/yp command files must not have extended ACLs.'
  desc "NIS/NIS+/yp files are part of the system's identification and authentication processes and are, therefore, critical to system security. ACLs on these files could result in unauthorized modification, which could compromise these processes and the system."
  desc 'check', 'Verify NIS/NIS+/yp files have no extended ACLs.
# ls -lL /var/yp/*
If the permissions include a "+" the file has an extended ACL, this is a finding.'
  desc 'fix', 'Remove the optional ACL from the file.
# chacl -z /var/yp/*'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36317r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22318'
  tag rid: 'SV-38284r1_rule'
  tag stig_id: 'GEN001361'
  tag gtitle: 'GEN001361'
  tag fix_id: 'F-31572r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
