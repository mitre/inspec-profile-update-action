control 'SV-89625' do
  title 'The MQ Appliance network device must prohibit password reuse for a minimum of five generations.'
  desc "Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

To meet password policy requirements, passwords need to be changed at specific policy-based intervals. 

If the MQ Appliance network device allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements. 

For LDAP authentication, the authentication server is responsible for enforcing password policy. When the LDAP server is not available, password policy is enforced by the MQ Appliance's RBM Password Policy."
  desc 'check', 'Log on to the MQ Appliance WebGUI as a privileged user. Go to Administration (gear icon) >> Access >> RBM Settings. 

Verify the Authentication Method is set to LDAP. 

Expand Password Policy. 

Verify the (local) MQ Password Policy Reuse History is set to a minimum of "5". 

If MQ is not set to LDAP authentication or if the local password policy is not configured to meet the requirement, this is a finding.'
  desc 'fix', 'Log on to the MQ Appliance WebGUI as a privileged user. Go to Administration (gear icon) >> Access> > RBM Settings. 

Set Authentication Method to LDAP. 

Configure LDAP server connection as required. 

Expand Password Policy. 

In Password Policy, check the Control Reuse check box and set reuse history to a minimum of "5".'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 NDM'
  tag check_id: 'C-74809r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74951'
  tag rid: 'SV-89625r1_rule'
  tag stig_id: 'MQMH-ND-000570'
  tag gtitle: 'SRG-APP-000165-NDM-000253'
  tag fix_id: 'F-81567r1_fix'
  tag 'documentable'
  tag mitigations: 'MQMH-ND-000570'
  tag mitigation_control: 'In the MQ Appliance WebGUI, go to Administration >> Access >> RBM Settings.'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
