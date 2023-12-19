control 'SV-16819' do
  title 'No documented configuration management process exists for VirtualCenter changes.'
  desc 'VirtualCenter objects might have multiple permissions for users and or groups. Permissions are applied hierarchically downward on these objects. For each permission the administrator must decide if the permission applies only to that immediate object, or downward to all sub objects.  Permissions may be overridden by setting different permissions on a lower object.  These situations can create confusion and permissions that were thought to be limited might actually be elevated.  Furthermore, all changes take affect immediately not requiring users to log off and log back in. Configuration management is critical for all modifications since the new change may override previously configured permissions.'
  desc 'check', 'Request a copy of the configuration management process document.  If the document is incomplete or does not exist, this is a finding.'
  desc 'fix', 'Document a configuration management process for all VirtualCenter modifications.'
  impact 0.5
  ref 'DPMS Target ESX Architecture and Policy'
  tag check_id: 'C-16236r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15878'
  tag rid: 'SV-16819r1_rule'
  tag stig_id: 'ESX0790'
  tag gtitle: 'No documented configuration management process'
  tag fix_id: 'F-15838r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
