control 'SV-100049' do
  title 'The vRA PostgreSQL database security updates and patches must be installed in a timely manner in accordance with site policy.'
  desc 'Security flaws with software applications, including database management systems, are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant software updates (e.g., patches, service packs, and hot fixes). Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously. 

Organization-defined time periods for updating security-relevant software may vary based on a variety of factors including, for example, the security category of the information system or the criticality of the update (i.e., severity of the vulnerability related to the discovered flaw). 

This requirement will apply to software patch management solutions that are used to install patches across the enclave and also to applications themselves that are not part of that patch management solution. For example, many browsers today provide the capability to install their own patch software. Patch criticality, as well as system criticality, will vary. Therefore, the tactical situations regarding the patch management process will also vary. This means that the time period utilized must be a configurable parameter. Time frames for application of security-relevant software updates may be dependent upon the Information Assurance Vulnerability Management (IAVM) process.

The application will be configured to check for and install security-relevant software updates within an identified time period from the availability of the update. The specific time period will be defined by an authoritative source (e.g. IAVM, CTOs, DTMs, and STIGs).'
  desc 'check', 'Obtain supporting documentation from the ISSO.

Review the policies and procedures used to ensure that all security-related upgrades are being installed within the configured time period directed by an authoritative source.

If all security-related upgrades are not being installed within the configured time period directed by an authoritative source, this is a finding.'
  desc 'fix', 'Ensure that patches and updates from an authoritative source are applied at least within 24 hours after they have been received.'
  impact 0.7
  ref 'DPMS Target VMware vRealize Automation 7.x PostgreSQL'
  tag check_id: 'C-89091r1_chk'
  tag severity: 'high'
  tag gid: 'V-89399'
  tag rid: 'SV-100049r1_rule'
  tag stig_id: 'VRAU-PG-000330'
  tag gtitle: 'SRG-APP-000456-DB-000390'
  tag fix_id: 'F-96141r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
