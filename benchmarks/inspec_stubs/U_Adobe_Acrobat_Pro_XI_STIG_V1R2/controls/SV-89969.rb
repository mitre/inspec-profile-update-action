control 'SV-89969' do
  title 'The Adobe Acrobat Pro XI latest security-related software updates must be installed.'
  desc 'Security flaws with software applications are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant software updates (e.g., patches, service packs, and hot fixes). Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously.

This requirement will apply to software patch management solutions that are used to install patches across the enclave and also to applications that are not part of that patch management solution. For example, many browsers today provide the capability to install their own patch software. Patch criticality, as well as system criticality, will vary. Therefore, the tactical situations regarding the patch management process will also vary. This means that the time period used must be a configurable parameter. Time frames for application of security-relevant software updates may be dependent upon the Information Assurance Vulnerability Management (IAVM) process.

The application will be configured to check for and install security-relevant software updates within an identified time period from the availability of the update. The specific time period will be defined by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).'
  desc 'check', 'Open Adobe Acrobat Pro XI.

Navigate to and click on Help >> About Adobe Acrobat XI Pro.

Verify that the latest security-related software updates by Adobe are being applied.

If the latest security-related software updates by Adobe are not being applied, this is a finding.'
  desc 'fix', 'Apply the latest security-related software updates to the Adobe Acrobat XI Pro application.'
  impact 0.7
  ref 'DPMS Target Adobe Acrobat Pro XI'
  tag check_id: 'C-75073r1_chk'
  tag severity: 'high'
  tag gid: 'V-75289'
  tag rid: 'SV-89969r1_rule'
  tag stig_id: 'ADBP-XI-001075'
  tag gtitle: 'SRG-APP-000456'
  tag fix_id: 'F-81905r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
