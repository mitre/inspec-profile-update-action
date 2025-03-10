control 'SV-253515' do
  title 'DocAve must use multifactor authentication for network access to privileged accounts.'
  desc "Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased. 

Multifactor authentication requires using two or more factors to achieve authentication. 

Factors include: 
(i) Something a user knows (e.g., password/PIN); 
(ii) Something a user has (e.g., cryptographic identification device, token); or 
(iii) Something a user is (e.g., biometric). 

Multifactor authentication decreases the attack surface by virtue of the fact that attackers must obtain two factors, a physical token or a biometric and a PIN, in order to authenticate. It is not enough to simply steal a user's password to obtain access. A privileged account is defined as an information system account with authorizations of a privileged user. 

Network access is defined as access to an information system by a user (or a process acting on behalf of a user) communicating through a network (e.g., local area network, wide area network, or the internet)."
  desc 'check', 'DocAve supports Client Certificate Authentication for multi-factor authentication, which requires both Windows Authentication and Client Certificate Authentication enabled in DocAve. Settings must be configured in IIS and DocAve. The IIS configuration under DCAV-00-000057 should be performed first.

Check the DocAve Client Certificate Authentication configuration. 
- Log on to DocAve with admin account.
- On the Control Panel page, in the Authentication Manager section, click "Authentication Manager". 
- Verify that "Client Certificate Authentication" is enabled.

If "Client Certificate Authentication" is not enabled, this is a finding.

Check the DocAve Windows Authentication configuration.
- Log on to DocAve with admin account.
- On the Control Panel page, in the Authentication Manager section, click "Authentication Manager". 
- Verify that "Windows Authentication" is enabled.

If "Windows Authentication" is not enabled, this is a finding.'
  desc 'fix', 'Configure DocAve to use Smart Card Authentication. Settings must be configured in IIS and DocAve. The IIS configuration under DCAV-00-000057 should be performed first.

Log on to DocAve with admin account.
- On the Control Panel page, in the Authentication Manager section, click "Authentication Manager".
- Click "Enable" in the Action column of the Client Certificate Authentication row to enable client certificate authentication.
- Click "Enable" in the Action column of the Windows Authentication row to enable Windows Authentication.
- Back to the Control Panel page, in the Account Manager section, click "Account Manager". 
- Click "Users-Add User".
- Select Client Certificate User from the drop-down list in the "What kind of user would you like to add?" field.
- Specify the user in the Windows User/Group Name field.
- Add this user to one or more DocAve groups.
- Save the settings.'
  impact 0.7
  ref 'DPMS Target AvePoint DocAve 6'
  tag check_id: 'C-56967r836518_chk'
  tag severity: 'high'
  tag gid: 'V-253515'
  tag rid: 'SV-253515r836520_rule'
  tag stig_id: 'DCAV-00-000056'
  tag gtitle: 'SRG-APP-000149'
  tag fix_id: 'F-56918r836519_fix'
  tag 'documentable'
  tag cci: ['CCI-000765']
  tag nist: ['IA-2 (1)']
end
