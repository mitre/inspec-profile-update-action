control 'SV-242197' do
  title 'The SMS must install updates on the TPS for application software files, signature definitions, detection heuristics, and vendor-provided rules when new releases are available in accordance with organizational configuration management policy and procedures.'
  desc 'Failing to update malicious code protection mechanisms, including application software files, signature definitions, and vendor-provided rules, leaves the system vulnerable to exploitation by recently developed attack methods and programs. 

The TPS is a key malicious code protection mechanism in the enclave infrastructure. To ensure this protection is responsive to changes in malicious code threats, IDPS components must be updated, including application software files, anti-virus signatures, detection heuristics, vendor-provided rules, and vendor-provided signatures.

Updates must be installed in accordance with the CCB procedures for the local organization. However, at a minimum: 
1. Updates designated as critical security updates by the vendor must be installed immediately.
2. Updates for signature definitions, detection heuristics, and vendor-provided rules must be installed immediately.
3. Updates for application software are installed in accordance with the CCB procedures.
4. Prior to automatically installing updates, either manual or automated integrity and authentication checking is required, at a minimum, for application software updates.'
  desc 'check', '1. In the Trend Micro SMS, navigate to "Profiles", and "Digital Vaccines". 
2. Under "Auto DV Activation" if "Automatic Download", and "Automatic Activation" are not enabled, this is a finding.'
  desc 'fix', '1. In the Trend Micro SMS, navigate to "Profiles", and "Digital Vaccines". 
2. Under "Auto DV Activation", select edit.
   a. Check Automatic Download.
   b. Check Automatic Activation. 
   c. Click OK.'
  impact 0.7
  ref 'DPMS Target Trend Micro TippingPoint IDPS'
  tag check_id: 'C-45472r710132_chk'
  tag severity: 'high'
  tag gid: 'V-242197'
  tag rid: 'SV-242197r754437_rule'
  tag stig_id: 'TIPP-IP-000330'
  tag gtitle: 'SRG-NET-000246-IDPS-00205'
  tag fix_id: 'F-45430r710133_fix'
  tag 'documentable'
  tag cci: ['CCI-001240']
  tag nist: ['SI-3 b']
end
