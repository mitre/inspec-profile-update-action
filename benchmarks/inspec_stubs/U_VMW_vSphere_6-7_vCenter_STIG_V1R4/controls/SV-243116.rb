control 'SV-243116' do
  title 'The vCenter Server must disable Password and Windows integrated authentication.'
  desc 'All forms of authentication other than CAC must be disabled. Password authentication can be temporarily re-enabled for emergency access to the local SSO domain accounts but it must be disable as soon as CAC authentication is functional.'
  desc 'check', 'Note: For vCenter Server Windows, this is not applicable.

From the vSphere Client go to Administration >> Single Sign-On >> Configuration >> Smart Card Authentication.

If "Smart card authentication" is not enabled and "Password and windows session authentication" is not disabled, this is a finding.'
  desc 'fix', 'From the vSphere Client go to Administration >> Single Sign-On >> Configuration >> Smart Card Authentication. Next to "Authentication methods", click "Edit". Click the "Enable smart card authentication" radio button and click "Save".

To re-enable password authentication for troubleshooting purposes, run the following command on the vCenter server:

/opt/vmware/bin/sso-config.sh -set_authn_policy -pwdAuthn true -winAuthn false -certAuthn false -securIDAuthn false -t vsphere.local'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46391r719589_chk'
  tag severity: 'medium'
  tag gid: 'V-243116'
  tag rid: 'SV-243116r879887_rule'
  tag stig_id: 'VCTR-67-000061'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-46348r719590_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
