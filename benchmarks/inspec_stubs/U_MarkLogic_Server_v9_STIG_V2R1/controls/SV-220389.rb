control 'SV-220389' do
  title 'Security-relevant software updates to MarkLogic Server must be installed within the time period directed by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).'
  desc 'Security flaws with software applications, including database management systems, are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant software updates (e.g., patches, service packs, and hot fixes). Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously. 

Organization-defined time periods for updating security-relevant software may vary based on a variety of factors including, for example, the security category of the information system or the criticality of the update (i.e., severity of the vulnerability related to the discovered flaw). 

This requirement will apply to software patch management solutions used to install patches across the enclave and also to applications themselves not part of that patch management solution. For example, many browsers today provide the capability to install their own patch software. Patch criticality, as well as system criticality, will vary. Therefore, the tactical situations regarding the patch management process will also vary. This means that the time period utilized must be a configurable parameter. Time frames for application of security-relevant software updates may be dependent upon the Information Assurance Vulnerability Management (IAVM) process.

The application will be configured to check for and install security-relevant software updates within an identified time period from the availability of the update. The specific time period will be defined by an authoritative source (e.g. IAVM, CTOs, DTMs, and STIGs).

MarkLogic releases full software package updates that include all relevant security updates as well as enhancements and bug fixes. Larger updates are usually released quarterly, with smaller updates provided as needed between quarterly releases. Security updates are not packaged separately.'
  desc 'check', 'Obtain evidence that package updates are consistently applied to MarkLogic within the time frame defined for each patch.

The most recent releases of MarkLogic Server can be found at https://help.marklogic.com. 

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges. 

Check the MarkLogic version identified in the upper left side of the Admin Interface and compare it to the versions found on the MarkLogic website.

Obtain evidence that package updates are consistently applied to MarkLogic within the time frame defined for each patch. 

If such evidence cannot be obtained, or the evidence that is obtained indicates a pattern of noncompliance, this is a finding.'
  desc 'fix', 'Institute and adhere to policies and procedures to ensure that package updates are consistently applied to MarkLogic within the time allowed.

MarkLogic releases full software package updates that include all relevant security updates as well as enhancements and bug fixes. Larger updates are usually released quarterly, with smaller updates provided as needed between quarterly releases. Security updates are not packaged separately.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22104r401618_chk'
  tag severity: 'medium'
  tag gid: 'V-220389'
  tag rid: 'SV-220389r855494_rule'
  tag stig_id: 'ML09-00-009200'
  tag gtitle: 'SRG-APP-000456-DB-000390'
  tag fix_id: 'F-22093r401619_fix'
  tag 'documentable'
  tag legacy: ['SV-110127', 'V-101023']
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
