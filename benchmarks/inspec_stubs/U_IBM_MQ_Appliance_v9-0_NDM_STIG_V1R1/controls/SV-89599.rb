control 'SV-89599' do
  title 'Access to the MQ Appliance network element must use two or more authentication servers for the purpose of granting administrative access.'
  desc "All accounts used for access to the MQ Appliance network device are privileged or system-level accounts. Therefore, if account management functions are not automatically enforced, an attacker could gain privileged access to a vital element of the network security architecture. 

The use of Authentication, Authorization, and Accounting (AAA) affords the best methods for controlling user access, authorization levels, and activity logging. By enabling AAA on the routers in conjunction with an authentication server such as TACACS+ or RADIUS, the administrators can easily add or remove user accounts, add or remove command authorizations, and maintain a log of user activity. 

The use of an authentication server provides the capability to assign device administrators to tiered groups that contain their privilege level, which is used for authorization of specific commands. 

This control does not include emergency administration accounts that provide access to the MQ Appliance network device components in case of network failure. There must be only one such locally defined account. All other accounts must be defined. All other accounts must be created and managed on the site's authentication server (e.g., RADIUS, LDAP, or Active Directory). This requirement is applicable to account management functions provided by the MQ Appliance network device."
  desc 'check', 'Log on to the MQ Appliance WebGUI as a privileged user. Go to Administration (gear icon) >> Access >> RBM Settings. 

Review LDAP configuration. Verify the LDAP configuration includes a Load Balancer Group that includes two or more authentication servers. 

If the LDAP configuration does not include a Load Balancer Group that includes two or more authentication servers, this is a finding.'
  desc 'fix', 'Log on to the MQ Appliance WebGUI as a privileged user. Go to Administration (gear icon) >> Access >> RBM Settings. 

Set Authentication Method to LDAP. Configure a Load Balancer Group that includes two or more LDAP authentication servers. 

Configure LDAP server connection settings as required.'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 NDM'
  tag check_id: 'C-74783r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74925'
  tag rid: 'SV-89599r1_rule'
  tag stig_id: 'MQMH-ND-000060'
  tag gtitle: 'SRG-APP-000023-NDM-000205'
  tag fix_id: 'F-81541r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
