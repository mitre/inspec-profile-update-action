control 'SV-216879' do
  title 'The vCenter Server for Windows must enable revocation checking for certificate based authentication.'
  desc 'The system must establish the validity of the user supplied identity certificate using OCSP and/or CRL revocation checking.'
  desc 'check', '1. Login to the Platform Services Controller web interface with administrator@vsphere.local from

https://<FQDN or IP of PSC>/psc

In an embedded deployment the Platform Services Controller host name or IP address is the same as the vCenter Server host name or IP address.

If you specified a different SSO domain during installation, log in as administrator@<mydomain>.

2. Browse to Single Sign-On > Configuration.

3. Click the "Smart Card Configuration" tab

4. Click the "Certificate Revocation Settings" tab

If "Revocation Check" does not show as enabled, this is a finding.'
  desc 'fix', '1. Login to the Platform Services Controller web interface with administrator@vsphere.local from

https://<FQDN or IP of PSC>/psc

In an embedded deployment the Platform Services Controller host name or IP address is the same as the vCenter Server host name or IP address.

If you specified a different SSO domain during installation, log in as administrator@<mydomain>.

2. Browse to Single Sign-On > Configuration.

3. Click the "Smart Card Configuration" tab

4. Click the "Certificate Revocation Settings" tab

5. Click the "Enable Revocation Check" button

By default the PSC will use the CRL from the certificate to check revocation check status. OCSP with CRL fallback is recommended but this setting is site specific and should be configured appropriately.'
  impact 0.5
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18110r366351_chk'
  tag severity: 'medium'
  tag gid: 'V-216879'
  tag rid: 'SV-216879r612237_rule'
  tag stig_id: 'VCWN-65-000060'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-18108r366352_fix'
  tag 'documentable'
  tag legacy: ['V-94823', 'SV-104653']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
