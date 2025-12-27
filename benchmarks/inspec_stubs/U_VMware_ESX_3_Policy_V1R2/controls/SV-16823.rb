control 'SV-16823' do
  title 'There is no up-to-date documentation of the virtualization infrastructure.'
  desc 'With the creation of virtual machines, the actual virtual network topology becomes increasingly complex.  The topology changes when a virtual machine is created, added to a virtual switch or port group, moved to another virtualization server, etc.  With the dynamic nature of the virtualization environment, administrators of the virtualization environment will maintain up to date documentation for all virtual machines, virtual switches, IP addresses, MAC addresses, etc.'
  desc 'check', 'Request a copy of all the virtualization infrastructure documentation.  Documentation must include all ESX Servers, virtual machines, IP addresses, MAC addresses, virtual switches, operating systems, and any virtual applications.  If the documentation does include all of these components, this is a finding.'
  desc 'fix', 'Develop up-to-date documentation for the virtualization infrastructure.'
  impact 0.5
  ref 'DPMS Target ESX Architecture and Policy'
  tag check_id: 'C-16241r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15882'
  tag rid: 'SV-16823r1_rule'
  tag stig_id: 'ESX0860'
  tag gtitle: 'Virtual infrastructure documents not up-to-date'
  tag fix_id: 'F-15842r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
  tag ia_controls: 'DCHW-1, DCSW-1'
end
