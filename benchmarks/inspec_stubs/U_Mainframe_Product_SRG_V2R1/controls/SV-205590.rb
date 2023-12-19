control 'SV-205590' do
  title 'The Mainframe Product must install security-relevant software updates within the time period directed by an authoritative source (e.g., IAVMs, CTOs, DTMs, and STIGs).'
  desc 'Security flaws with software applications are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant software updates (e.g., patches, service packs, and hot fixes). Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously. 

Organization-defined time periods for updating security-relevant software may vary based on a variety of factors including, for example, the security category of the information system or the criticality of the update (i.e., severity of the vulnerability related to the discovered flaw). 

This requirement will apply to software patch management solutions that are used to install patches across the enclave and also to applications themselves that are not part of that patch management solution. For example, many browsers today provide the capability to install their own patch software. Patch criticality, as well as system criticality will vary. Therefore, the tactical situations regarding the patch management process will also vary. This means that the time period used must be a configurable parameter. Time frames for application of security-relevant software updates may be dependent upon the Information Assurance Vulnerability Management (IAVM) process.

The application will be configured to check for and install security-relevant software updates within an identified time period from the availability of the update. The specific time period will be defined by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).'
  desc 'check', 'Review Mainframe Product published Version release information.

Review authoritative sources.

If security relevant updates are not installed as required, this is a finding.'
  desc 'fix', 'Install security relevant updates as required.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5856r299997_chk'
  tag severity: 'medium'
  tag gid: 'V-205590'
  tag rid: 'SV-205590r851355_rule'
  tag stig_id: 'SRG-APP-000456-MFP-000345'
  tag gtitle: 'SRG-APP-000456'
  tag fix_id: 'F-5856r299998_fix'
  tag 'documentable'
  tag legacy: ['SV-82975', 'V-68485']
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
