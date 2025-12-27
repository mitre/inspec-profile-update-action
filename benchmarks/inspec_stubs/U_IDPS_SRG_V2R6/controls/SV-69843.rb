control 'SV-69843' do
  title 'The IDPS must automatically install updates to signature definitions, detection heuristics, and vendor-provided rules.'
  desc "Failing to automatically update malicious code protection mechanisms, including application software files, signature definitions, and vendor-provided rules, leaves the system vulnerable to exploitation by recently developed attack methods and programs. An automatic update process ensures this important task is performed without the need for system administrator intervention.

The IDPS is a key malicious code protection mechanism in the enclave infrastructure. To ensure this protection is responsive to changes in malicious code threats, IDPS components must be automatically updated, including anti-virus signatures, detection heuristics, vendor-provided rules, and vendor-provided signatures.

If a DoD patch management server or update repository having the tested/verified updates is available for the IDPS component, the components must be configured to automatically check this server/site for updates and install new updates. 

If a DoD server/site is not available, the component must be configured to automatically check a trusted vendor site for updates. A trusted vendor is either commonly used by DoD, specifically approved by DoD, the vendor from which the equipment was purchased, or approved by the local program's CCB."
  desc 'check', 'Verify the IDPS automatically installs updates to signature definitions, detection heuristics, and vendor-provided rules.

If the IDPS does not automatically install updates to signature definitions, detection heuristics, and vendor-provided rules, this is a finding.'
  desc 'fix', 'Configure the IDPS to automatically install updates to signature definitions, detection heuristics, and vendor-provided rules.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-56177r1_chk'
  tag severity: 'medium'
  tag gid: 'V-55597'
  tag rid: 'SV-69843r2_rule'
  tag stig_id: 'SRG-NET-000251-IDPS-00178'
  tag gtitle: 'SRG-NET-000251-IDPS-00178'
  tag fix_id: 'F-60469r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001247']
  tag nist: ['SI-3 (2)']
end
