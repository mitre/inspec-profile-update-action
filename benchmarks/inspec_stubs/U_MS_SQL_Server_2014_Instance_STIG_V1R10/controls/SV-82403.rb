control 'SV-82403' do
  title 'Security-relevant software updates to SQL Server must be installed within the time period directed by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).'
  desc 'Security flaws with software applications, including database management systems, are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant software updates (e.g., patches, service packs, and hot fixes). Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously. 

Organization-defined time periods for updating security-relevant software may vary based on a variety of factors including, for example, the security category of the information system or the criticality of the update (i.e., severity of the vulnerability related to the discovered flaw). 

Patch criticality, as well as system criticality, will vary. Therefore, the tactical situations regarding the patch management process will also vary. This means that the time period utilized must be a configurable parameter. Time frames for application of security-relevant software updates may be dependent upon the Information Assurance Vulnerability Management (IAVM) process.

The application will be configured to check for and install security-relevant software updates within an identified time period from the availability of the update. The specific time period will be defined by an authoritative source (e.g. IAVM, CTOs, DTMs, and STIGs).'
  desc 'check', 'Obtain evidence that software patches are consistently applied to SQL Server within the time frame defined for each patch.

If such evidence cannot be obtained, or the evidence that is obtained indicates a pattern of noncompliance, this is a finding.'
  desc 'fix', 'Institute and adhere to policies and procedures to ensure that patches are consistently applied to SQL Server within the time allowed.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2014'
  tag check_id: 'C-68483r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67913'
  tag rid: 'SV-82403r1_rule'
  tag stig_id: 'SQL4-00-035400'
  tag gtitle: 'SRG-APP-000456-DB-000390'
  tag fix_id: 'F-74029r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
