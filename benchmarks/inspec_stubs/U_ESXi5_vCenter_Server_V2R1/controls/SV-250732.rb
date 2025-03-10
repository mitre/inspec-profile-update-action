control 'SV-250732' do
  title 'The vCenter Server administrative users must have the correct roles assigned.'
  desc 'Administrative users must only be assigned privileges they require. Least Privilege requires that these privileges must only be assigned if needed, to reduce risk of confidentiality, availability or integrity loss.'
  desc 'check', %q(Check that roles are created in vCenter with the required granularity of privilege for the organization's administrator types, and that these roles are assigned to the correct, site-specific users:
Log into the vCenter Server System using the vSphere Client as a vCenter Server System Administrator. 
Go to "Home>> Administration>> Roles" and verify that a role exists for each of the administrator privilege sets the organization requires and allows. 
Right click on each Role name and select "Edit". Verify under "All Privileges>> Virtual Machines" that only site-specific, required checkboxes are selected. 

If the organization does not require roles for administrator privilege sets, this is a finding.

If a role does not exist for each of the organization-required, administrator privilege sets, this is a finding.)
  desc 'fix', %q(Create roles in vCenter with the required granularity of privilege for the organization's administrator types, and ensure that these roles are assigned to the correct, site-specific users. As a vCenter Server administrator, log into the vCenter Server with the vSphere Client. 
Go to "Home>> Administration>> Roles" and create a role for each of the administrator privilege sets the organization requires and allows. 
Right click on each role name and select "Edit". Verify under "All Privileges>> Virtual Machines" that only site-specific, required checkboxes are selected.)
  impact 0.5
  ref 'DPMS Target VMware vCenter Server Version 5'
  tag check_id: 'C-54167r799884_chk'
  tag severity: 'medium'
  tag gid: 'V-250732'
  tag rid: 'SV-250732r799886_rule'
  tag stig_id: 'VCENTER-000012'
  tag gtitle: 'SRG-APP-000133'
  tag fix_id: 'F-54121r799885_fix'
  tag 'documentable'
  tag legacy: ['SV-51408', 'V-39550']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
