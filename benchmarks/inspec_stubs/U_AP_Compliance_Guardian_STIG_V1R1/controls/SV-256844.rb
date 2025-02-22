control 'SV-256844' do
  title 'Compliance Guardian must use multifactor authentication for network access to privileged accounts.'
  desc "Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased. 

Multifactor authentication requires using two or more factors to achieve authentication. Factors include: 
(i) Something a user knows (e.g., password/PIN); 
(ii) Something a user has (e.g., cryptographic identification device, token); or 
(iii) Something a user is (e.g., biometric).

Multifactor authentication decreases the attack surface by virtue of the fact that attackers must obtain two factors, a physical token or a biometric and a PIN, in order to authenticate. It is not enough to simply steal a user's password to obtain access. A privileged account is defined as an information system account with authorizations of a privileged user.

Network access is defined as access to an information system by a user (or a process acting on behalf of a user) communicating through a network (e.g., local area network, wide area network, or the internet).

"
  desc 'check', 'Compliance Guardian supports Client Certificate Authentication for multifactor authentication, which requires that both Windows Authentication and Client Certificate Authentication are enabled in Compliance Guardian.

Check the Compliance Guardian Client Certificate Authentication configuration. 
- Log on to Compliance Guardian with admin account.
- On the Control Panel page in the General Security section, click "Authentication Manager".
- Verify that the Client Certificate Authentication option is enabled.

If Client Certificate Authentication is not enabled, this is a finding.

Check the Compliance Guardian Windows Authentication configuration.
- Log on to Compliance Guardian with admin account.
- On the Control Panel page in the General Security section, click "Authentication Manager". 
- Verify that the "Windows Authentication" option is enabled.

If "Windows Authentication" is not enabled, this is a finding.'
  desc 'fix', 'Configure Compliance Guardian to use Smart Card Authentication, which is required to enable Client Certificate Authentication and Windows Authentication in both IIS Manager and Compliance Guardian.

On the Compliance Guardian Manager server, open IIS Manager.
- Open the "Authentication" settings under IIS.
- Enable the "Active Directory Client Certificate Authentication" and "Windows Authentication" options.
- Expand "Sites" and click "Compliance Guardian site". The default site name is "ComplianceGuardian4Site".
- Open the SSL Settings of ComplianceGuardian4Site under IIS.
- Make sure the "Require SSL" checkbox is selected.
- Open the Authentication Settings of ComplianceGuardian4Site under IIS.
- Make sure the status of "Windows Authentication" is "Enabled".
- Expand ComplianceGuardian4Site, Trust (virtual path).
- Open the SSL Settings of Trust (virtual path) under IIS. 
- Make sure the "Require SSL" checkbox is selected and the option of "Client Certificates" is selected as required.
- Restart ComplianceGuardian4 Application Pool and Website.

On Compliance Guardian side:
- Log on to Compliance Guardian with admin account.
- On the Control Panel page in the General Security section, click "Authentication Manager".
- Click the "Enable link" button on the "Client Certificate Authentication" row to enable client certificate authentication.
- Click the "Enable link" button on the "Windows Authentication" row to enable Windows Authentication.
- Back in the Control Panel page in the Account section, click "Users". 
- Navigate to "Add User" page.
- Select "Client Certificate User" from the drop-down list in the "User Type" field.
- Specify the user in the "Windows User/Group Name" field.
- Add this user to one or more Compliance Guardian groups.
- Save the settings.'
  impact 0.7
  ref 'DPMS Target AvePoint Compliance Guardian'
  tag check_id: 'C-60519r890140_chk'
  tag severity: 'high'
  tag gid: 'V-256844'
  tag rid: 'SV-256844r890142_rule'
  tag stig_id: 'APCG-00-000025'
  tag gtitle: 'SRG-APP-000149'
  tag fix_id: 'F-60462r890141_fix'
  tag satisfies: ['SRG-APP-000149', 'SRG-APP-000150', 'SRG-APP-000177', 'SRG-APP-000391', 'SRG-APP-000392', 'SRG-APP-000402', 'SRG-APP-000403']
  tag 'documentable'
  tag cci: ['CCI-000187', 'CCI-000765', 'CCI-000766', 'CCI-001953', 'CCI-001954', 'CCI-002009', 'CCI-002010']
  tag nist: ['IA-5 (2) (a) (2)', 'IA-2 (1)', 'IA-2 (2)', 'IA-2 (12)', 'IA-2 (12)', 'IA-8 (1)', 'IA-8 (1)']
end
