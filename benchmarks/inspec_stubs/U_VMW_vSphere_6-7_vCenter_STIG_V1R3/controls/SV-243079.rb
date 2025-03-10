control 'SV-243079' do
  title 'The vCenter Server must implement Active Directory authentication.'
  desc 'The vCenter Server must ensure users are authenticated with an individual authenticator prior to using a group authenticator. Using Active Directory for authentication provides more robust account management capabilities.'
  desc 'check', 'From the vSphere Web Client, go to Administration >> Single Sign-On >> Configuration. 

Click the "Identity Sources" tab.

If there is no identity source of type "Active Directory", this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Administration >> Single Sign-On >> Configuration. 

Click the "Add identity source".

Select either "Active Directory over LDAP" or "Active Directory" and configure appropriately. 

Note: Windows Integrated Authentication requires that the vCenter server be joined to AD before configuration via Administration >> Single Sign-On >> Configuration >> Active Directory Domain.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46354r863036_chk'
  tag severity: 'medium'
  tag gid: 'V-243079'
  tag rid: 'SV-243079r863038_rule'
  tag stig_id: 'VCTR-67-000009'
  tag gtitle: 'SRG-APP-000153'
  tag fix_id: 'F-46311r863037_fix'
  tag 'documentable'
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
