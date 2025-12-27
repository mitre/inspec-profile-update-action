control 'SV-25965' do
  title 'NIS/NIS+/yp command files must not have extended ACLs.'
  desc "NIS/NIS+/yp files are part of the system's identification and authentication processes and are, therefore, critical to system security. ACLs on these files could result in unauthorized modification, which could compromise these processes and the system."
  desc 'check', 'Determine if any NIS/NIS+/yp command files have an extended ACL.  If so, this is a finding.'
  desc 'fix', 'Remove the extended ACL from the NS/NIS+/yp command file(s).'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29114r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22318'
  tag rid: 'SV-25965r1_rule'
  tag stig_id: 'GEN001361'
  tag gtitle: 'GEN001361'
  tag fix_id: 'F-26117r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
