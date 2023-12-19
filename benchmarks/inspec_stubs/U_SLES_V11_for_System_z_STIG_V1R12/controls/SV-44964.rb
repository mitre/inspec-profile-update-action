control 'SV-44964' do
  title 'NIS/NIS+/yp command files must not have extended ACLs.'
  desc "NIS/NIS+/yp files are part of the system's identification and authentication processes and are critical to system security.  ACLs on these files could result in unauthorized modification, which could compromise these processes and the system."
  desc 'check', "Verify NIS/NIS+/yp files have no extended ACLs.
# ls -lL /var/yp/*
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /var/yp/*'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42382r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22318'
  tag rid: 'SV-44964r1_rule'
  tag stig_id: 'GEN001361'
  tag gtitle: 'GEN001361'
  tag fix_id: 'F-38387r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
