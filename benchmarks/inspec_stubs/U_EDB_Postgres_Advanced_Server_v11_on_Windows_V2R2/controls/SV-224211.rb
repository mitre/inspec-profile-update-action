control 'SV-224211' do
  title 'Security-relevant software updates to the EDB Postgres Advanced Server must be installed within the time period directed by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).'
  desc 'Security flaws with software applications, including database management systems, are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant software updates (e.g., patches, service packs, and hot fixes). Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously.

Organization-defined time periods for updating security-relevant software may vary based on a variety of factors including, for example, the security category of the information system or the criticality of the update (i.e., severity of the vulnerability related to the discovered flaw).

This requirement will apply to software patch management solutions that are used to install patches across the enclave and also to applications themselves that are not part of that patch management solution. For example, many browsers today provide the capability to install their own patch software. Patch criticality, as well as system criticality, will vary. Therefore, the tactical situations regarding the patch management process will also vary. This means the time period utilized must be a configurable parameter. Timeframes for application of security-relevant software updates may be dependent upon the Information Assurance Vulnerability Management (IAVM) process.

The application will be configured to check for and install security-relevant software updates within an identified time period from the availability of the update. The specific time period will be defined by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).'
  desc 'check', 'Obtain evidence that software patches are obtained from EnterpriseDB and are consistently applied to the DBMS within the timeframe defined for each patch.

If such evidence cannot be obtained, or the evidence that is obtained indicates a pattern of noncompliance, this is a finding.

To check which version of EDB Postgres Advanced Server is installed, execute the following SQL statement:

 SELECT version();

If the version returned by the above query is at a lower version level than required, this is a finding.

If an administrator is not registered on the EDB Support Portal with an email address for monitoring technical alerts, this is a finding.'
  desc 'fix', 'Institute and adhere to policies and procedures to ensure that patches are consistently obtained from EnterpriseDB and applied to the DBMS within the time allowed.

Ensure that a monitored email address is registered as a user on the EDB support portal and is receiving technical alerts.'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25884r495650_chk'
  tag severity: 'medium'
  tag gid: 'V-224211'
  tag rid: 'SV-224211r508023_rule'
  tag stig_id: 'EP11-00-009900'
  tag gtitle: 'SRG-APP-000456-DB-000390'
  tag fix_id: 'F-25872r495651_fix'
  tag 'documentable'
  tag legacy: ['SV-109547', 'V-100443']
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
