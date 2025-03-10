control 'SV-29511' do
  title 'Local users exist on a workstation in a domain.'
  desc 'To minimize potential points of attack, local users, other than built-in accounts such as Administrator and Guest accounts, should not exist on a workstation in a domain.  Users should always log onto workstations in a domain domain with their domain accounts.  This does not apply to laptop PCs which are designed to function both on the domain and off the domain.'
  desc 'fix', 'Configure the system to restrict the existence of local user accounts.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag severity: 'low'
  tag gid: 'V-1148'
  tag rid: 'SV-29511r1_rule'
  tag gtitle: 'Local Users Exist on a Workstation'
  tag fix_id: 'F-5764r1_fix'
  tag false_positives: 'This does not apply to laptops that are designed to function both as part of a domain and separate from it.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'IAAC-1'
end
