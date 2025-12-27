control 'SV-16861' do
  title 'Virtual machine requirements are not documented before creating a virtual machine.'
  desc 'Guest operating systems may require different resources depending on the server function. A database or email server will require more resources than a basic Windows Domain Controller.  Therefore, proper planning is required to determine what servers will be built within the virtualization server environment.  

To properly create virtual machines within the virtualization server environment, a minimal list of requirements will be determined.  These requirements are the amount of memory, amount of required disk space, the networking card assignment, required media, and proper disk mode to be used.'
  desc 'check', 'Request a copy of the virtual machine requirements documentation. If no documentation exists, this is a finding.'
  desc 'fix', 'Develop virtual machine requirements documentation.'
  impact 0.3
  ref 'DPMS Target ESX Architecture and Policy'
  tag check_id: 'C-16275r1_chk'
  tag severity: 'low'
  tag gid: 'V-15919'
  tag rid: 'SV-16861r1_rule'
  tag stig_id: 'ESX1160'
  tag gtitle: 'Virtual machine requirements not documented'
  tag fix_id: 'F-15873r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Guest Administrator]']
  tag ia_controls: 'ECSC-1'
end
