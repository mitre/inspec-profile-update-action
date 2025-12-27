control 'SV-251880' do
  title '(U) McAfee VirusScan must have the current security patches installed.'
  desc 'Security flaws with software applications are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant software updates (e.g., patches, service packs, and hot fixes). Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously.

Organization-defined time periods for updating security-relevant software may vary based on a variety of factors including, for example, the security category of the information system or the criticality of the update (i.e., severity of the vulnerability related to the discovered flaw).

This requirement will apply to software patch management solutions that are used to install patches across the enclave and also to applications that are not part of that patch management solution. For example, many browsers today provide the capability to install their own patch software. Patch criticality, as well as system criticality, will vary. Therefore, the tactical situations regarding the patch management process will also vary. This means that the time period used must be a configurable parameter. Time frames for application of security-relevant software updates depend on the Information Assurance Vulnerability Management (IAVM) process.

The application will be configured to check for and install security-relevant software updates within an identified time period from the availability of the update. The specific time period will be defined by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).'
  desc 'check', '(CUI) McAfee VirusScan 8.8 is no longer supported by the vendor. If McAfee VirusScan 8.8 is being used, this is a finding.'
  desc 'fix', '(CUI) Install the minimum mandated version of ENS specified in OPORD 16-0080 FRAGO 6.'
  impact 0.7
  ref 'DPMS Target McAfee VirusScan 8.8 Managed Client'
  tag check_id: 'C-55337r816541_chk'
  tag severity: 'high'
  tag gid: 'V-251880'
  tag rid: 'SV-251880r816543_rule'
  tag stig_id: 'DTAM171'
  tag gtitle: 'SRG-APP-000456'
  tag fix_id: 'F-30701r811465_fix'
  tag 'documentable'
  tag legacy: ['SV-58229', 'V-45399']
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
