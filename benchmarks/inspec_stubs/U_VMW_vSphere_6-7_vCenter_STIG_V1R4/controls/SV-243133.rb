control 'SV-243133' do
  title 'The vCenter Server must disable Password and Windows integrated authentication.'
  desc 'All forms of authentication other than CAC must be disabled. Password authentication can be temporarily reenabled for emergency access to the local SSO domain accounts, but it must be disabled as soon as CAC authentication is functional.'
  desc 'check', 'Note: For vCenter Server Appliance, this is not applicable.

From the vSphere Client, go to Administration >> Single Sign-On >> Configuration >> Smart Card Authentication.

If "Smart card authentication" is not enabled and "Password and windows session authentication" is not disabled, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Administration >> Single Sign-On >> Configuration >> Smart Card Authentication. 

Next to "Authentication methods", click "Edit". 

Click the "Enable smart card authentication" radio button and click "Save".

To reenable password authentication for troubleshooting purposes, run the following command on the vCenter server:

C:\\Program Files\\VMware\\VCenter server\\VMware Identity Services\\sso-config.bat -set_authn_policy -pwdAuthn true -winAuthn false -certAuthn false -securIDAuthn false -t vsphere.local'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46408r719640_chk'
  tag severity: 'medium'
  tag gid: 'V-243133'
  tag rid: 'SV-243133r879887_rule'
  tag stig_id: 'VCTR-67-000078'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-46365r719641_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
