control 'SV-29512' do
  title 'Local users must not exist on a system in a domain.'
  desc 'To minimize potential points of attack, local users, other than built-in accounts such as Administrator and Guest accounts, must not exist on a workstation in a domain.  Users must log onto workstations in a domain with their domain accounts.'
  desc 'fix', 'Limit local user accounts on domain-joined systems.  Remove any unauthorized local accounts.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag severity: 'low'
  tag gid: 'V-1148'
  tag rid: 'SV-29512r3_rule'
  tag gtitle: 'Local Users Exist on a Workstation'
  tag fix_id: 'F-53561r3_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
