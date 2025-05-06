control 'SV-16845' do
  title 'Virtual machines are removed from the site without approval documentation.'
  desc 'From a theft perspective, virtual machines are easy to copy and move to a person’s USB drive, portable hard drive, etc. An insider could potentially move the organization’s entire data center on any type of removable media that had sufficient space.'
  desc 'check', 'Request the approval documentation from the IAO/SA that the site uses for all virtual machines taken off site.  If no documentation exists, this is a finding.'
  desc 'fix', 'Create documentation to use for virtual machines taken off site.'
  impact 0.5
  ref 'DPMS Target ESX Architecture and Policy'
  tag check_id: 'C-16263r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15903'
  tag rid: 'SV-16845r1_rule'
  tag stig_id: 'ESX1070'
  tag gtitle: 'Virtual machines are removed without documentation'
  tag fix_id: 'F-15864r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Machine Administrator]']
  tag ia_controls: 'ECSC-1'
end
