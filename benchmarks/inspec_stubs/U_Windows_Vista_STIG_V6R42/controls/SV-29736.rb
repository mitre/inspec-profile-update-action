control 'SV-29736' do
  title 'A Windows system has an incorrect default DCOM authorization level.'
  desc 'The DCOM default authentication level has been detected to be below the required setting. If the authentication level is None, then any user can access any object on the system without authentication.'
  desc 'check', 'Open a command prompt.
Execute “Dcomcnfg.exe”.
In the “Component Services” window, navigate to Component Services -> Computer -> My Computer 
Right-click “My Computer” and select “Properties”.
Select the “Default Properties” tab.
If the “Default Authentication Level” is set to “None” or “Call”, this is a finding.'
  desc 'fix', 'Fortify DCOMs default permissions.  This should be thoroughly tested to verify DCOM objects continue to function under tightened security.
Open a command prompt.
Execute “Dcomcnfg.exe”.
In the “Component Services” window, navigate to Component Services -> Computer -> My Computer 
Right-click “My Computer” and select “Properties”.
Select the “Default Properties” tab.
 Select a “Default Authentication Level” other than “None” or “Call”.  For sensitive systems, an authentication level of “Packet Privacy” is recommended. 
Click OK.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-40668r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6825'
  tag rid: 'SV-29736r2_rule'
  tag gtitle: 'DCOM - Default Authorization Level'
  tag fix_id: 'F-36078r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
