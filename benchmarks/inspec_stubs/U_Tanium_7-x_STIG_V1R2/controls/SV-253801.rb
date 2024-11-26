control 'SV-253801' do
  title 'The Tanium application must install security-relevant software updates within the time period directed by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).'
  desc 'Security flaws with software applications are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant software updates (e.g., patches, service packs, and hot fixes). Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously. 

Organization-defined time periods for updating security-relevant software may vary based on a variety of factors including, for example, the security category of the information system or the criticality of the update (i.e., severity of the vulnerability related to the discovered flaw). 

This requirement will apply to software patch management solutions that are used to install patches across the enclave and also to applications that are not part of that patch management solution. For example, many browsers can install their own patch software. Patch criticality, as well as system criticality, will vary. Therefore, the tactical situations regarding the patch management process will also vary. This means the time period used must be a configurable parameter. Time frames for application of security-relevant software updates may depend on the Information Assurance Vulnerability Management (IAVM) process.

The application will be configured to check for and install security-relevant software updates within an identified time period from the availability of the update. The specific time period will be defined by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).'
  desc 'check', 'Verify all components of the Tanium application have been updated within 60 days of vulnerability being announced by Tanium. Critical Vulnerabilities must be updated within 30 days. 

Consult with the Tanium system administrator to review the documented time window designated for updates.

If a window of time is not defined or does not specify a reoccurring frequency, this is a finding.

1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web user interface (UI) and log on with multifactor authentication. 

2. Click "Administration" on the top navigation banner. 

3. Under "Configuration", select "Solutions".

If any module has the text "Update to" a newer (greater) version number compared to the installed version number in the Tanium Modules section of the page, this is a finding.

If the Tanium application is an "airgap" installation, work with the Tanium technical system administrator to determine if the modules are up to date.'
  desc 'fix', 'Consult with the Tanium system administrator to review the documented time window designated for updates.

If a window of time is not defined or does not specify a reoccurring frequency, work with the Tanium administrator to document this.

1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web UI and log on with multifactor authentication. 

2. Click "Administration" on the top navigation banner. 

3. Under "Configuration", select "Solutions".

If any module has the text "Update to" a newer (greater) version number compared to the installed version number in the Tanium Modules section of the page, work with the Tanium administrator to update those modules or content.

If the Tanium application is an "airgap" installation, work with the Tanium technical system administrator to determine if the modules are up to date.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57253r842429_chk'
  tag severity: 'medium'
  tag gid: 'V-253801'
  tag rid: 'SV-253801r850286_rule'
  tag stig_id: 'TANS-00-001565'
  tag gtitle: 'SRG-APP-000456'
  tag fix_id: 'F-57204r842430_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
