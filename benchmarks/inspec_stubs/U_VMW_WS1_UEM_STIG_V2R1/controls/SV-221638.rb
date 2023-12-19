control 'SV-221638' do
  title 'The Workspace ONE UEM server must be configured with an enterprise certificate for signing policies (if function is not automatically implemented during Workspace ONE UEM server install).'
  desc 'It is critical that only authorized certificates are used for key activities such as code signing for system software updates, code signing for integrity verification, and policy signing. Otherwise, there is no assurance that a malicious actor has not inserted itself in the process of packaging the code or policy. For example, messages signed with an invalid certificate may contain links to malware, which could lead to the installation or distribution of that malware on DoD information systems, leading to compromise of DoD sensitive information and other attacks. Therefore, the Workspace ONE UEM server must have the capability to configure the enterprise certificate.

SFR ID: FMT_SMF.1.1(2) c.8,
FMT_POL_EXT.1.1'
  desc 'check', 'Review the Workspace ONE UEM server configuration settings and verify the server is configured with an enterprise certificate for signing policies.

On the MDM console, do the following:
1. Authenticate to the Workspace ONE UEM console as the administrator.
2. Navigate to Groups & Settings >> All Settings >> System >> Advanced >> Policy Signing Certificate.

If the "Policy Signing Certificate" choice is not present under "Advanced", this is a finding.

If the "Policy Signing Certificate" choice is present, but the Workspace ONE UEM server is not configured with an enterprise certificate for signing policies, this is a finding.

For Android:
No additional checks are required.

For iOS:
3. Navigate to Groups & Settings >> All Settings >> Devices & Users >> Apple >> Profiles.

If "Sign Profiles" (Requires Server SSL Certificate)" is set to "DISABLED" or is set to "ENABLED" and no signing certificate is listed, this is a finding.'
  desc 'fix', 'Configure the Workspace ONE UEM server with an enterprise certificate for signing policies.

To enable the presence of the "Policy Signing Certificate" choice on the Workspace ONE UEM (MDM) console, execute the following database query on the Server after logging in with database administrative privilege:

UPDATE dbo.SystemCodeCategory
SET ResourceID = 7192
WHERE SystemCodeCategoryID = 370

On the MDM console, do the following:
1. Authenticate to the Workspace ONE UEM console as the administrator.
2. Navigate to Groups & Settings >> All Settings >> System >> Advanced >> Policy Signing Certificate.
3. Upload the valid Policy Signing Certificate to the Workspace ONE UEM server to configure the Workspace ONE UEM Agents.

For Android:
Once a Policy Signing Certificate is uploaded, no additional configuration is necessary.

To configure the Apple iOS MDM Agent:
a. Navigate to Groups & Settings >> All Settings >> Devices & Users >> Apple >> Profiles.
b. Ensure "ENABLED" is selected for "Sign Profiles (Requires Server SSL Certificate).
c. Click "UPLOAD" to upload a Signing Certificate and then click "SAVE".

To update or replace a Policy Signing Certificate:
a. Navigate to Groups & Settings >> All Settings >> System >> Advanced >> Policy Signing Certificate.
b. Click "Replace", "Choose File", and "Upload" to upload the new certificate, then click "Save" to configure the enterprise certificate for signing policies.
c. Verify that the Policy Signing Certificate properties have been updated.

For Android:
Once a new Policy Signing Certificate is uploaded, no additional configuration is necessary.

To update the Apple iOS MDM Agent:
a. Navigate to Groups & Settings >> All Settings >> Devices & Users >> Apple >> Profiles.
b. Click "Override" for Current Setting".
c. Click "REPLACE" to upload a new Signing Certificate, upload the certificate, and then click "SAVE".
d. Verify that the Policy Signing Certificate properties have been updated.'
  impact 0.5
  ref 'DPMS Target VMware Workspace ONE UEM'
  tag check_id: 'C-23353r416752_chk'
  tag severity: 'medium'
  tag gid: 'V-221638'
  tag rid: 'SV-221638r588007_rule'
  tag stig_id: 'VMW1-00-000470'
  tag gtitle: 'PP-MDM-411051'
  tag fix_id: 'F-23342r416753_fix'
  tag 'documentable'
  tag legacy: ['SV-111275', 'V-102319']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
