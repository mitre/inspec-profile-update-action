control 'SV-243115' do
  title 'The vCenter Server must enable revocation checking for certificate-based authentication.'
  desc 'The system must establish the validity of the user-supplied identity certificate using OCSP and/or CRL revocation checking.'
  desc 'check', 'From the vSphere Client, go to Administration >> Single Sign-On >> Configuration >> Smart Card Authentication. 

Under Smart card authentication settings >> Certificate revocation, verify that "Revocation check" does not show as disabled.

If "Revocation check" shows as disabled, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Administration >> Single Sign-On > Configuration >> Smart Card Authentication. 

Under Smart card authentication settings >> Certificate revocation, click the "Edit" button.

By default, the PSC will use the CRL from the certificate to check revocation check status. 

OCSP with CRL fallback is recommended, but this setting is site specific and should be configured appropriately.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46390r719586_chk'
  tag severity: 'medium'
  tag gid: 'V-243115'
  tag rid: 'SV-243115r719588_rule'
  tag stig_id: 'VCTR-67-000060'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-46347r719587_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
