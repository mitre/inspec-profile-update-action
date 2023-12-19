control 'SV-252183' do
  title 'Security-relevant software updates to MongoDB must be installed within the time period directed by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).'
  desc 'Security flaws with software applications, including database management systems, are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant software updates (e.g., patches, service packs, and hot fixes). Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously.

Organization-defined time periods for updating security-relevant software may vary based on a variety of factors including, for example, the security category of the information system or the criticality of the update (i.e., severity of the vulnerability related to the discovered flaw).

This requirement will apply to software patch management solutions that are used to install patches across the enclave and also to applications themselves that are not part of that patch management solution. For example, many browsers today provide the capability to install their own patch software. Patch criticality, as well as system criticality, will vary. Therefore, the tactical situations regarding the patch management process will also vary. This means that the time period utilized must be a configurable parameter. Time frames for application of security-relevant software updates may be dependent upon the Information Assurance Vulnerability Management (IAVM) process.

The application will be configured to check for and install security-relevant software updates within an identified time period from the availability of the update. The specific time period will be defined by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).'
  desc 'check', 'Review the organizational or site-specific software update policy and verify that MongoDB has been updated consistent with the time frame specified by the policy.

The current major version of MongoDB can be found here: https://docs.mongodb.com/v4.4/release-notes/

This link will show the major version of MongoDB. To find the minor version within that release select the appropriate sublink.

For example, to see the latest 4.4 minor releases in MongoDB, select the Release Notes for 4.4. This will show all minor releases and their notes. For example: 4.4.9, 4.4.8, 4.4.6, 4.4.5, etc.

If MongoDB has not been updated to the necessary major and minor release in accordance with the policy, this is a finding.'
  desc 'fix', 'Institute and adhere to the policies and procedures to ensure that MongoDB is updated consistent with the organizational or site-specific software update policy and time frame.

Update MongoDB to the necessary major and minor release in accordance with the organizational or site-specific policy.'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55639r855525_chk'
  tag severity: 'medium'
  tag gid: 'V-252183'
  tag rid: 'SV-252183r855526_rule'
  tag stig_id: 'MD4X-00-006400'
  tag gtitle: 'SRG-APP-000456-DB-000390'
  tag fix_id: 'F-55589r813930_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
