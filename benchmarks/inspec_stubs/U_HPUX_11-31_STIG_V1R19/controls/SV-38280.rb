control 'SV-38280' do
  title 'All network services daemon files must not have extended ACLs.'
  desc 'Restricting permission on daemons will protect them from unauthorized modification and possible system compromise.'
  desc 'check', %q(Check Content:
Verify network services daemon files have no extended ACLs.
# cat /etc/inetd.conf | sed -e 's/^[ \t]*//' | tr '\011' ' ' | tr -s ' ' | grep -v '^#' | cut -f6,6 -d " " | xargs -n1 ls -lL

If the permissions include a "+", the file has an extended ACL, and this is a finding.)
  desc 'fix', 'Remove the optional ACL from the file.
# chacl -z <path>/< network-services-daemon>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36312r3_chk'
  tag severity: 'medium'
  tag gid: 'V-22313'
  tag rid: 'SV-38280r1_rule'
  tag stig_id: 'GEN001190'
  tag gtitle: 'GEN001190'
  tag fix_id: 'F-31567r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
