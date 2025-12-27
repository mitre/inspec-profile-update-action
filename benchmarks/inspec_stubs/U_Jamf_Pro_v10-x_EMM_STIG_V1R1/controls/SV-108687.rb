control 'SV-108687' do
  title 'Authentication of Jamf Pro EMM server accounts must be configured so they are implemented either via an Authentication Gateway Service (AGS) which connects to the site DoD Identity Access Management (IdAM) environment that utilizes CAC authentication or via strong password controls for the administrator local accounts.'
  desc 'A comprehensive account management process that includes automation helps to ensure the accounts designated as requiring attention are consistently and promptly addressed. If an attacker compromises an account, the entire Jamf Pro EMM server infrastructure is at risk. Providing automated support functions for the management of accounts will ensure only active accounts will be granted access with the proper authorization levels. These objectives are best achieved by configuring the Jamf Pro EMM server to leverage an enterprise authentication mechanism (e.g., Microsoft Active Directory Kerberos).

SFR ID: FIA'
  desc 'check', 'Interview the site ISSM. 

Determine if the site has connected Jamf Pro EMM to an Authentication Gateway Service (AGS) which connects to the DoD Identity Access Management (IdAM) environment that uses CAC authentication. 

- If YES, verify the AGS implementation has been reviewed using the Application Layer Gateway SRG. Verify the Jamf Pro EMM server is configured to connect to the AGS:
1. Go to the server console.
2. Open "Settings".
3. Select "SSO" (Single Sign-on).
4. Verify Single Sign-on Authentication is enabled and connection to the AGS using SAML-based protocol is set up.

- If NO, verify strong password controls for the administrator local accounts are in place. (Verified by JAMF-10-100700 to JAMF-10-100820.)

If Jamf Pro EMM is not connected to an Authentication Gateway Service (AGS) which connects to the DoD Identity Access Management (IdAM) environment that uses CAC authentication or has not been configured to use strong password controls for the administrator local accounts, this is a finding.'
  desc 'fix', 'Implement one of the following options:

Option #1. Connect Jamf Pro EMM to an Authentication Gateway Service (AGS) which connects to the DoD Identity Access Management (IdAM) environment that uses CAC authentication. Note: Jamf requires AGS to support SAML.

- Set up AGS/IdAM environment.
- Connect the Jamf pro EMM to the AGS:
1. Open "Settings".
2. Select "SSO" (Single Sign-on).
3. Select "Edit".
4. Enable Single Sign-on Authentication.
5. Complete the appropriate settings to connect Jamf Pro EMM to the AGS using SAML-based protocol.
6. Click "Save".

Note: If Option #1 is used, requirements JAMF-10-100700 to JAMF-10-10820 are Not Applicable and requirement JAMF-10-200040 is Applicable - Configurable.

Option #2. Implement strong password policy for admin local accounts. Configure the server password policy (JAMF-10-100700 to JAMF-10-10820).

Note: If Option #2 is used, requirement JAMF-10-200040 is Not Applicable.'
  impact 0.5
  ref 'DPMS Target JAMF v10.x EMM'
  tag check_id: 'C-98433r1_chk'
  tag severity: 'medium'
  tag gid: 'V-99583'
  tag rid: 'SV-108687r1_rule'
  tag stig_id: 'JAMF-10-000685'
  tag gtitle: 'PP-MDM-991000'
  tag fix_id: 'F-105267r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
