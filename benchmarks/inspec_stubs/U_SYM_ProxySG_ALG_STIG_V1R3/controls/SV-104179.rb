control 'SV-104179' do
  title 'Symantec ProxySG storing secret or private keys must use FIPS-approved key management technology and processes in the production and control of private/secret cryptographic keys.'
  desc "Private key data is used to prove that the entity presenting a public key certificate is the certificate's rightful owner. Compromise of private key data allows an adversary to impersonate the key holder. 

Private key data associated with software certificates, including those issued to an ALG, must be generated and protected in at least a FIPS 140-2 Level 1 validated cryptographic module. For Proxy SG, as long as the FIPS-compliant suite is configured for use and configured in compliance with the FIPS cert manual requirements, key management should be in compliance using the following instructions. Symantec HSM may be used; however, it may require an additional license."
  desc 'check', 'If the FIPS-compliant suite is configured for use, this is not a finding. If HSM is used, then verify that the ProxySG is using FIPS-approved key management.

1. Log on to the Web Management Console. 
2. Click Configuration >> SSL >> HSM. 
3. Click the "HSM" and "HSM Keyring" tabs and Verify that these options have been configured.
4. Verify with the ProxySG administrator that the HSM specified is FIPS 140-2 compliant.
5. Click Configuration >> Proxy Settings >> SSL Proxy.
6. Verify that the Issuer Keyring is set to the HSM Keyring from step 3.

If Symantec ProxySG storing secret or private keys does not use FIPS-approved key management technology and processes in the production and control of private/secret cryptographic keys, this is a finding.'
  desc 'fix', 'As long as the FIPS-compliant suite is configured for use and configured in compliance with the FIPS cert manual requirements, key management should be in compliance using the following instructions.

1. Log on to the Web Management Console. 
2. Click Configuration >> SSL >> HSM. 
3. Click the "HSM" and "HSM Keyring" tabs and configure these options per the guidance in the ProxySG Administration Guide, Chapter 9: Managing the SSL Proxy, Section G: Working with an HSM Appliance.
4. Click Configuration >> Proxy Settings >> SSL Proxy.
5. Select the HSM Keyring in the Issuer Keyring field and click "Apply".

Note: As long as the FIPS-compliant suite is being used and configured in compliance with the FIPS cert manual requirements, key management should be in compliance as part of this.'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93411r3_chk'
  tag severity: 'medium'
  tag gid: 'V-94225'
  tag rid: 'SV-104179r2_rule'
  tag stig_id: 'SYMP-AG-000050'
  tag gtitle: 'SRG-NET-000062-ALG-000092'
  tag fix_id: 'F-100341r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
