control 'SV-216880' do
  title 'The vCenter Server for Windows must disable Password and Windows integrated authentication.'
  desc 'All forms of authentication other than CAC must be disabled. Password authentication can be temporarily re-enabled for emergency access to the local SSO domain accounts but it must be disable as soon as CAC authentication is functional.'
  desc 'check', '1. Login to the Platform Services Controller web interface with administrator@vsphere.local from

https://<FQDN or IP of PSC>/psc

In an embedded deployment the Platform Services Controller host name or IP address is the same as the vCenter Server host name or IP address.

If you specified a different SSO domain during installation, log in as administrator@<mydomain>.

2. Browse to Single Sign-On >> Configuration.

3. Click the "Smart Card Configuration" tab, click the "Edit" button next to “Authentication Configuration”.

If the selection box next to “Password and Windows session authentication” is checked, this is a finding.'
  desc 'fix', '1. Login to the Platform Services Controller web interface with administrator@vsphere.local from

https://<FQDN or IP of PSC>/psc

In an embedded deployment the Platform Services Controller host name or IP address is the same as the vCenter Server host name or IP address.

If you specified a different SSO domain during installation, log in as administrator@<mydomain>.

2. Browse to Single Sign-On >> Configuration.

3. Click the "Smart Card Configuration" tab, click the "Edit" button next to “Authentication Configuration”.

4. Check the box next to “Password and Windows session authentication”. Click "OK".

To re-enable password authentication for troubleshooting run the following command from the PSC:

/opt/vmware/bin/sso-config.sh -set_authn_policy -pwdAuthn true -winAuthn false -certAuthn false -securIDAuthn false -t vsphere.local'
  impact 0.3
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18111r366354_chk'
  tag severity: 'low'
  tag gid: 'V-216880'
  tag rid: 'SV-216880r612237_rule'
  tag stig_id: 'VCWN-65-000061'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-18109r366355_fix'
  tag 'documentable'
  tag legacy: ['SV-104655', 'V-94825']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
