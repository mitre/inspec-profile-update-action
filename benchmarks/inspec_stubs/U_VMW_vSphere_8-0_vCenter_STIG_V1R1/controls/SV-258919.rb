control 'SV-258919' do
  title 'The vCenter Server must enable revocation checking for certificate-based authentication.'
  desc 'The system must establish the validity of the user-supplied identity certificate using Online Certificate Status Protocol (OCSP) and/or Certificate Revocation List (CRL) revocation checking.

'
  desc 'check', 'If a federated identity provider is configured and used for an identity source and supports Smartcard authentication, this is not applicable.

From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Identity Provider >> Smart Card Authentication.

Under Smart card authentication settings >> Certificate revocation, verify "Revocation check" does not show as disabled.

If "Revocation check" shows as disabled, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Identity Provider >> Smart Card Authentication.

Under Smart card authentication settings >> Certificate revocation, click the "Edit" button.

Configure revocation checking per site requirements. OCSP with CRL failover is recommended.

Note: If FIPS mode is enabled on vCenter, OCSP revocation validation may not function and CRL bay be used instead.

By default, both locations are pulled from the cert. CRL location can be overridden in this screen, and local responders can be specified via the sso-config command line tool. See the vSphere documentation for more information.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 vCenter'
  tag check_id: 'C-62659r934413_chk'
  tag severity: 'medium'
  tag gid: 'V-258919'
  tag rid: 'SV-258919r934415_rule'
  tag stig_id: 'VCSA-80-000080'
  tag gtitle: 'SRG-APP-000175'
  tag fix_id: 'F-62568r934414_fix'
  tag satisfies: ['SRG-APP-000175', 'SRG-APP-000392', 'SRG-APP-000401', 'SRG-APP-000403']
  tag 'documentable'
  tag cci: ['CCI-000185', 'CCI-001954', 'CCI-001991', 'CCI-002010']
  tag nist: ['IA-5 (2) (b) (1)', 'IA-2 (12)', 'IA-5 (2) (d)', 'IA-8 (1)']
end
