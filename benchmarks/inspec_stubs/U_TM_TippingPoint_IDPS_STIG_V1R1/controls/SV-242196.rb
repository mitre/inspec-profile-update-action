control 'SV-242196' do
  title 'The TPS must automatically install updates to signature definitions, detection heuristics, and vendor-provided rules.'
  desc "Failing to automatically update malicious code protection mechanisms, including application software files, signature definitions, and vendor-provided rules, leaves the system vulnerable to exploitation by recently developed attack methods and programs. An automatic update process ensures this important task is performed without the need for system administrator intervention.

The TPS is a key malicious code protection mechanism in the enclave infrastructure. To ensure this protection is responsive to changes in malicious code threats, TPS components must be automatically updated, including anti-virus signatures, detection heuristics, vendor-provided rules, and vendor-provided signatures.

If a DoD patch management server or update repository having the tested/verified updates is available for the TPS component, the components must be configured to automatically check this server/site for updates and install new updates. 

If a DoD server/site is not available, the component must be configured to automatically check a trusted vendor site for updates. A trusted vendor is either commonly used by DoD, specifically approved by DoD, the vendor from which the equipment was purchased or approved by the local program's CCB."
  desc 'check', '1. In the Trend Micro SMS, navigate to "Profiles", and "Digital Vaccines". 
2. Under "Auto DV Activation", if "Automatic Download", and "Automatic Activation" are not enabled, this is a finding.'
  desc 'fix', '1. In the Trend Micro SMS, navigate to "Profiles", and "Digital Vaccines". 
2. Under "Auto DV Activation", select edit. 
   a. Check Automatic Download.
   b. Check Automatic Activation. 
   c. Click OK.'
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint IDPS'
  tag check_id: 'C-45471r710129_chk'
  tag severity: 'medium'
  tag gid: 'V-242196'
  tag rid: 'SV-242196r710131_rule'
  tag stig_id: 'TIPP-IP-000320'
  tag gtitle: 'SRG-NET-000251-IDPS-00178'
  tag fix_id: 'F-45429r710130_fix'
  tag 'documentable'
  tag cci: ['CCI-001247']
  tag nist: ['SI-3 (2)']
end
