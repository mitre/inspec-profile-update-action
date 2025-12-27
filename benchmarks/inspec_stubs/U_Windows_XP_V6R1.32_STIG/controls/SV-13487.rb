control 'SV-13487' do
  title 'ACLs for disabled services do not conform to minimum standards.'
  desc 'When configuring either the startup mode or access control list for a service, you must configure the other as well. When a service is explicitly disabled, its ACL should also be secured by changing the default ACL from Everyone Full Control to grant Administrators and SYSTEM Full Control and Interactive Read access.'
  desc 'check', 'Windows 2003/XP/Vista - Use the "Security Configuration and Analysis" snap-in to analyze the system.
Expand the “Security Configuration and Analysis” object in the tree window. 
Expand the “System Services” object and select each applicable disabled Service.
(Disabled Services can be identified using the Control Panel’s Services applet.
Right click the Service and select Properties
Select ‘View Security’

If the ACLs for applicable disabled Services do not restrict permissions to Administrators, ‘full Control’, System ‘full control’, and Interactive ‘Read’, then this is a finding.


Note:  These are the Windows default settings.'
  desc 'fix', 'Create a Custom Security Template using the Security Template MMC Snap-in to set the permissions as required for disabled services.

Import the Custom Template into the Security Configuration and Analysis Snap-In and Select Configure Computer Now

Or import the Custom Template in to a Group Policy for application.

The administrator should have a thorough understanding of these tools before implementing settings with them.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-9572r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2371'
  tag rid: 'SV-13487r1_rule'
  tag gtitle: 'ACLs for disabled services'
  tag fix_id: 'F-58r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2'
end
