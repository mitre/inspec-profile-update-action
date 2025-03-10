control 'SV-218278' do
  title 'NIS/NIS+/yp command files must not have extended ACLs.'
  desc "NIS/NIS+/yp files are part of the system's identification and authentication processes and are critical to system security.  ACLs on these files could result in unauthorized modification, which could compromise these processes and the system."
  desc 'check', "Verify NIS/NIS+/yp files have no extended ACLs.
# ls -lL /var/yp/*
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /var/yp/*'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19753r561623_chk'
  tag severity: 'medium'
  tag gid: 'V-218278'
  tag rid: 'SV-218278r603259_rule'
  tag stig_id: 'GEN001361'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19751r561624_fix'
  tag 'documentable'
  tag legacy: ['V-22318', 'SV-64503']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
