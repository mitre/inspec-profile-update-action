control 'SV-93457' do
  title 'Tanium Server must install security-relevant software updates within the time period directed by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).'
  desc 'Security flaws with software applications are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant software updates (e.g., patches, service packs, and hot fixes). Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously.

Organization-defined time periods for updating security-relevant software may vary based on a variety of factors including, for example, the security category of the information system or the criticality of the update (i.e., severity of the vulnerability related to the discovered flaw).

This requirement will apply to software patch management solutions that are used to install patches across the enclave and also to applications themselves that are not part of that patch management solution. For example, many browsers today provide the capability to install their own patch software. Patch criticality, as well as system criticality will vary. Therefore, the tactical situations regarding the patch management process will also vary. This means that the time period used must be a configurable parameter. Time frames for application of security-relevant software updates may be dependent upon the Information Assurance Vulnerability Management (IAVM) process.

The application will be configured to check for and install security-relevant software updates within an identified time period from the availability of the update. The specific time period will be defined by an authoritative source (e.g. IAVM, CTOs, DTMs, and STIGs).'
  desc 'check', 'Consult with the Tanium System Administrator to review the documented time window designated for updates.

If a window of time is not defined, or does not specify a reoccurring frequency, this is a finding.

Using a web browser on a system that has connectivity to Tanium, access the Tanium web user interface (UI) and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console and then click on "Tanium Solutions".

If any module has the text "Upgrade to" a newer (greater) version number compared to the Installed version number in the Tanium Modules section of the page, this is a finding.

If the Tanium install is an "airgap" install, work with the Tanium Technical Account Manager (TAM) to determine if the modules are up to date.'
  desc 'fix', 'Work with the Tanium System Administrator to define the reoccurring time window designated for updates.

Update the system documentation to reflect this window of time.

Using a web browser on a system that has connectivity to Tanium, access the Tanium web UI and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console and then click on "Tanium Solutions".

Select any modules that indicate "Upgrade to" and proceed with importing the modules.'
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78327r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78751'
  tag rid: 'SV-93457r1_rule'
  tag stig_id: 'TANS-SV-000064'
  tag gtitle: 'SRG-APP-000456'
  tag fix_id: 'F-85493r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
