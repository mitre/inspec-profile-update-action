control 'SV-16744' do
  title 'Permissions have been changed on the /usr/sbin/esx* utilities'
  desc 'Configuring virtual switches may be performed by using predefined ESX Server commands. These commands are located in the /usr/bin of the file system hierarchy. Since these commands can create, disable, and modify existing configurations, they will be restricted to the root user only.  If other users were able to access these commands, inadvertent changes could potentially disable a virtual network.'
  desc 'check', 'Logon to the ESX Server service console, and perform the following to review the permissions on the esx* utilities.

# ls -lL /usr/sbin/esx* | less 

All permissions here should be 500 except for esxcfg-auth and esxupdate which should be 544. If they are not the correct permissions, this is a finding.'
  desc 'fix', 'Change the permissions to all esx* utilities to 500 except for esxcfg-auth and exsupdate which should be 544.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16027r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15805'
  tag rid: 'SV-16744r1_rule'
  tag stig_id: 'ESX0160'
  tag gtitle: 'Permissions have been changed on esx* utilities.'
  tag fix_id: 'F-15748r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
