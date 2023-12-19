control 'SV-95139' do
  title 'The Bromium Enterprise Controller (BEC) must remove all local Bromium accounts after setup is complete and use the account recovery procedures to recover the local account if network access using the Bromium Account of Last Resort is required.'
  desc "Since Bromium multifactor authentication is implemented through use of the enclave's directory service, the Bromium account of last resort cannot comply with the DoD requirement for multifactor authentication. Since local account password complexity requirements are not met, a weak password could be hacked, giving immediate privileged access to the BEC.

Bromium, Inc. recommends that the setup account and any other local accounts be removed from the BEC application. In the event of a system-wide failure to connect to the authentication server, system recovery, or other organization-defined emergency, an authorized and credentialed administrator of the host server, can recover the setup account or create another account when needed.  When the emergency is over, the account must once again be removed.

Note: Either create a new account and password or change the password in order to comply with BROM-00-000690."
  desc 'check', 'Ask the site representatives if they have developed and documented an emergency local account recovery procedure for the BEC Account of Last Resort. 

Examine the BEC SSP.
 
If the BEC has not developed and documented an emergency local account recovery procedure for the BEC Account of Last Resort, this is a finding.'
  desc 'fix', 'Remove all local accounts after setup. Use the Bromium system recovery process to either create another account or recover the setup account when needed.

1. Using the BEC server setup application, generate the password for the local Account of Last Resort using a FIPS 140-2 compliant password generator.
2. Configure the BEC and all BEC user accounts to leverage an external authentication server (e.g., Active Directory).
3. Upon successful configuration and connection of the BEC to the authentication server, remove the local BEC account.

In the event of a system-wide failure to connect to the authentication server, system recovery, or other organization-defined emergency:
1. Gain access to the Windows Server running BEC.
2. Run the BEC server setup application (BrBMSSettings.exe).
3. Click on "Database Settings".
4. Check the box next to "Request new administrator user".
5. Click "Save".

Remove the account once normal operations resume.

Either create a new account and password each time the account is retried or change the password each time the same account is recovered in order to comply with BROM-00-000690.'
  impact 0.7
  ref 'DPMS Target Bromium Secure Platform'
  tag check_id: 'C-80107r1_chk'
  tag severity: 'high'
  tag gid: 'V-80435'
  tag rid: 'SV-95139r1_rule'
  tag stig_id: 'BROM-00-000300'
  tag gtitle: 'SRG-APP-000149'
  tag fix_id: 'F-87241r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000765']
  tag nist: ['IA-2 (1)']
end
