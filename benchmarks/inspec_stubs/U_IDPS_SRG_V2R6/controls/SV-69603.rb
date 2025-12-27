control 'SV-69603' do
  title 'The IDPS must install updates for application software files, signature definitions, detection heuristics, and vendor-provided rules when new releases are available in accordance with organizational configuration management policy and procedures.'
  desc 'Failing to update malicious code protection mechanisms, including application software files, signature definitions, and vendor-provided rules, leaves the system vulnerable to exploitation by recently developed attack methods and programs. 

The IDPS is a key malicious code protection mechanism in the enclave infrastructure. To ensure this protection is responsive to changes in malicious code threats, IDPS components must be updated, including application software files, anti-virus signatures, detection heuristics, vendor-provided rules, and vendor-provided signatures.

Updates must be installed in accordance with the CCB procedures for the local organization. However, at a minimum: 

1. Updates designated as critical security updates by the vendor must be installed immediately.

2. Updates for signature definitions, detection heuristics, and vendor-provided rules must be installed immediately.

3. Updates for application software are installed in accordance with the CCB procedures.

4. Prior to automatically installing updates, either manual or automated integrity and authentication checking is required, at a minimum, for application software updates.'
  desc 'check', 'Verify the IDPS installs updates for application software files, signature definitions, detection heuristics, and vendor-provided rules when new releases are available in accordance with organizational configuration management policy and procedures.

If the IDPS does not install updates for application software files, signature definitions, detection heuristics, and vendor-provided rules when new releases are available in accordance with organizational configuration management policy and procedures, this is a finding.'
  desc 'fix', 'Configure the IDPS to install updates for application software files, signature definitions, detection heuristics, and vendor-provided rules when new releases are available in accordance with organizational configuration management policy and procedures.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-55981r1_chk'
  tag severity: 'medium'
  tag gid: 'V-55357'
  tag rid: 'SV-69603r1_rule'
  tag stig_id: 'SRG-NET-000246-IDPS-00205'
  tag gtitle: 'SRG-NET-000246-IDPS-00205'
  tag fix_id: 'F-60225r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001240']
  tag nist: ['SI-3 b']
end
