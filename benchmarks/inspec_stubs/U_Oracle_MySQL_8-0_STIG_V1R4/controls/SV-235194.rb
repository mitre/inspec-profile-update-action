control 'SV-235194' do
  title 'Security-relevant software updates to the MySQL Database Server 8.0 must be installed within the time period directed by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).'
  desc 'Security flaws with software applications, including database management systems, are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant software updates (e.g., patches, service packs, and hot fixes). Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously. 

Organization-defined time periods for updating security-relevant software may vary based on a variety of factors including, for example, the security category of the information system or the criticality of the update (i.e., severity of the vulnerability related to the discovered flaw). 

This requirement will apply to software patch management solutions that are used to install patches across the enclave and also to applications themselves that are not part of that patch management solution. For example, many browsers today provide the capability to install their own patch software. Patch criticality, as well as system criticality, will vary. Therefore, the tactical situations regarding the patch management process will also vary. This means that the time period utilized must be a configurable parameter. Time frames for application of security-relevant software updates may be dependent upon the Information Assurance Vulnerability Management (IAVM) process.

The application will be configured to check for and install security-relevant software updates within an identified time period from the availability of the update. The specific time period will be defined by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).'
  desc 'check', 'To check the version of the installed MySQL, run the following SQL statement:

select @@version;

The result will show the version, for example:
8.0.22-commercial

Obtain evidence that software MRU updates are consistently applied to MySQL Server within the time frame defined for each update. To be considered supported, Oracle must report that the version is supported by security patches to known vulnerability.  

Review the MySQL Support dates at the following link:
https://www.oracle.com/support/lifetime-support/resources.html

Review the MySQL Release notes page:
https://dev.mysql.com/doc/relnotes/mysql/8.0/en/
 
If MySQL Enterprise Edition 8.0 is not at the latest version, this is a finding.'
  desc 'fix', 'Institute and adhere to policies and procedures to ensure that patches are consistently applied to MySQL within the time allowed.'
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38413r623702_chk'
  tag severity: 'medium'
  tag gid: 'V-235194'
  tag rid: 'SV-235194r879827_rule'
  tag stig_id: 'MYS8-00-012300'
  tag gtitle: 'SRG-APP-000456-DB-000390'
  tag fix_id: 'F-38376r623703_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
