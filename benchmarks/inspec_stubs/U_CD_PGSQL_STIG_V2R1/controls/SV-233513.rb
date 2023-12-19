control 'SV-233513' do
  title 'Security-relevant software updates to PostgreSQL must be installed within the time period directed by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).'
  desc 'Security flaws with software applications, including database management systems, are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant software updates (e.g., patches, service packs, and hot fixes). Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously.

Organization-defined time periods for updating security-relevant software may vary based on a variety of factors including, for example, the security category of the information system or the criticality of the update (i.e., severity of the vulnerability related to the discovered flaw).

This requirement will apply to software patch management solutions that are used to install patches across the enclave and also to applications themselves that are not part of that patch management solution. For example, many browsers today provide the capability to install their own patch software. Patch criticality, as well as system criticality, will vary. Therefore, the tactical situations regarding the patch management process will also vary. This means that the time period utilized must be a configurable parameter. Time frames for application of security-relevant software updates may be dependent upon the Information Assurance Vulnerability Management (IAVM) process.

The application will be configured to check for and install security-relevant software updates within an identified time period from the availability of the update. The specific time period will be defined by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).'
  desc 'check', 'If new packages are available for PostgreSQL, they can be reviewed in the package manager appropriate for the server operating system:

To list the version of installed PostgreSQL using psql:

$ sudo su - postgres
$ psql --version

To list the current version of software for RPM:

$ rpm -qa | grep postgres

To list the current version of software for APT:

$ apt-cache policy postgres

All versions of PostgreSQL will be listed on:

http://www.postgresql.org/support/versioning/

All security-relevant software updates for PostgreSQL will be listed on:

http://www.postgresql.org/support/security/

If PostgreSQL is not at the latest version, this is a finding.

If PostgreSQL is not at the latest version and the evaluated version has CVEs (IAVAs), then this is a CAT I finding.'
  desc 'fix', 'Institute and adhere to policies and procedures to ensure that patches are consistently applied to PostgreSQL within the time allowed.'
  impact 0.5
  ref 'DPMS Target Crunchy Data PostgreSQL'
  tag check_id: 'C-36707r606762_chk'
  tag severity: 'medium'
  tag gid: 'V-233513'
  tag rid: 'SV-233513r606764_rule'
  tag stig_id: 'CD12-00-000300'
  tag gtitle: 'SRG-APP-000456-DB-000390'
  tag fix_id: 'F-36672r606763_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
