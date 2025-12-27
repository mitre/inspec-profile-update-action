control 'SV-206611' do
  title 'Security-relevant software updates to the DBMS must be installed within the time period directed by an authoritative source (e.g. IAVM, CTOs, DTMs, and STIGs).'
  desc 'Security flaws with software applications, including database management systems, are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant software updates (e.g., patches, service packs, and hot fixes). Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously. 

Organization-defined time periods for updating security-relevant software may vary based on a variety of factors including, for example, the security category of the information system or the criticality of the update (i.e., severity of the vulnerability related to the discovered flaw). 

This requirement will apply to software patch management solutions that are used to install patches across the enclave and also to applications themselves that are not part of that patch management solution. For example, many browsers today provide the capability to install their own patch software. Patch criticality, as well as system criticality, will vary. Therefore, the tactical situations regarding the patch management process will also vary. This means that the time period utilized must be a configurable parameter. Time frames for application of security-relevant software updates may be dependent upon the Information Assurance Vulnerability Management (IAVM) process.

The application will be configured to check for and install security-relevant software updates within an identified time period from the availability of the update. The specific time period will be defined by an authoritative source (e.g. IAVM, CTOs, DTMs, and STIGs).'
  desc 'check', 'Obtain evidence that software patches are consistently applied to the DBMS within the time frame defined for each patch.

If such evidence cannot be obtained, or the evidence that is obtained indicates a pattern of noncompliance, this is a finding.'
  desc 'fix', 'Institute and adhere to policies and procedures to ensure that patches are consistently applied to the DBMS within the time allowed.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6871r291501_chk'
  tag severity: 'medium'
  tag gid: 'V-206611'
  tag rid: 'SV-206611r617447_rule'
  tag stig_id: 'SRG-APP-000456-DB-000390'
  tag gtitle: 'SRG-APP-000456'
  tag fix_id: 'F-6871r291502_fix'
  tag 'documentable'
  tag legacy: ['V-58177', 'SV-72607']
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
