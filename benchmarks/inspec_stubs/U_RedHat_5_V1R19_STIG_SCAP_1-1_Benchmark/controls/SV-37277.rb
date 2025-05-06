control 'SV-37277' do
  title 'NIS/NIS+/yp command files must not have extended ACLs.'
  desc "NIS/NIS+/yp files are part of the system's identification and authentication processes and are critical to system security.  ACLs on these files could result in unauthorized modification, which could compromise these processes and the system."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /var/yp/*'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22318'
  tag rid: 'SV-37277r1_rule'
  tag stig_id: 'GEN001361'
  tag gtitle: 'GEN001361'
  tag fix_id: 'F-23574r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
