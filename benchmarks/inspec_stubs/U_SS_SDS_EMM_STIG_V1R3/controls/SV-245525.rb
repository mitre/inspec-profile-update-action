control 'SV-245525' do
  title 'The Samsung SDS EMM must be configured to leverage the MDM platform administrator accounts and groups for Samsung SDS EMM user identification and CAC authentication.'
  desc 'A comprehensive account management process that includes automation helps to ensure the accounts designated as requiring attention are consistently and promptly addressed. If an attacker compromises an account, the entire MDM server infrastructure is at risk. Providing automated support functions for the management of accounts will ensure only active accounts will be granted access with the proper authorization levels. These objectives are best achieved by configuring the MDM server to leverage an enterprise authentication mechanism (e.g., Microsoft Active Directory Kerberos).

SFR ID: FIA'
  desc 'check', 'Verify SDS EMM is leveraging the MDM platform administrator accounts and groups for user (system administrator) identification and CAC authentication.  

Use one of the following methods:

Method 1:
- Attempt to log on to the SDS EMM console using a CAC.  
- Verify CAC log on was successful.

Method 2:
- Log in to the SDS EMM console.
- Go to Settings >> Server >> Configuration.
- Click "CAC Sign-In".
- Verify CAC Sign-In has been set up.

If SDS EMM is not leveraging the MDM platform administrator accounts and groups for user (system administrator) identification and CAC authentication, this is a finding.'
  desc 'fix', 'Configure SDS EMM to leverage the MDM platform administrator accounts and groups for user (system administrator) identification and CAC authentication.  

Complete the following procedures:
1.  Follow necessary setup steps for Admin Registration, Tomcat Server Settings,  Directory Settings found on the top of page 536 of the Samsung SDS EMM 2.2.5.3 Administrator Guide.
(Refer to the "CAC Sign-In" section of the Appendix of the Samsung SDS EMM 2.2.5.3 Administrator Guide for detailed setting procedures in the CAC authentication/Directory Services environment for the SDS EMM)
2. Enable CAC Sign-In by the following procedure:
- Log in to the SDS EMM console.
- Go to Settings >> Server >> Configuration.
- Click "CAC Sign-In".
- Configure the "CAC Sign-In Settings", Port", and "Directory Service Name".
- Click Save.'
  impact 0.7
  ref 'DPMS Target Samsung SDS EMM'
  tag check_id: 'C-48800r744401_chk'
  tag severity: 'high'
  tag gid: 'V-245525'
  tag rid: 'SV-245525r744387_rule'
  tag stig_id: 'SSDS-00-000710'
  tag gtitle: 'PP-MDM-414002'
  tag fix_id: 'F-48757r744400_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
