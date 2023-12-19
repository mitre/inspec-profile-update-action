control 'SV-222614' do
  title 'Security-relevant software updates and patches must be kept up to date.'
  desc 'Security flaws with software applications are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant software updates (e.g., patches, service packs, and hot fixes). Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously.

Organization-defined time periods for updating security-relevant software may vary based on a variety of factors including, for example, the security category of the information system or the criticality of the update (i.e., severity of the vulnerability related to the discovered flaw).

This requirement will apply to software patch management solutions that are used to install patches across the enclave and also to applications themselves that are not part of that patch management solution. For example, many browsers today provide the capability to install their own patch software. Patch criticality, as well as system criticality will vary. Therefore, the tactical situations regarding the patch management process will also vary. This means that the time period utilized must be a configurable parameter. Time frames for application of security-relevant software updates may be dependent upon the Information Assurance Vulnerability Management (IAVM) process.

The application, or the patch management solution that is configured to patch the application, must be configured to check for and install security-relevant software updates and patches at least weekly. Patches must be applied immediately or in accordance with POA&Ms, IAVMs, CTOs, DTMs or other authoritative patching guidelines or sources.'
  desc 'check', 'Review the application documentation to identify application versions and patching.

Interview the application administrator and inquire about patching process.

Review IAVMs and CTOs to determine if the application is being updated in accordance with authoritative sources.

If application updates are not checked on at least on a weekly basis and applied immediately or in accordance with POA&Ms, IAVMs, CTOs, DTMs or other authoritative patching guidelines or sources, this is a finding.'
  desc 'fix', 'Check for application updates at least weekly and apply patches immediately or in accordance with POA&Ms, IAVMs, CTOs, DTMs or other authoritative patching guidelines or sources.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24284r493750_chk'
  tag severity: 'medium'
  tag gid: 'V-222614'
  tag rid: 'SV-222614r849497_rule'
  tag stig_id: 'APSC-DV-002630'
  tag gtitle: 'SRG-APP-000456'
  tag fix_id: 'F-24273r493751_fix'
  tag 'documentable'
  tag legacy: ['SV-84903', 'V-70281']
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
