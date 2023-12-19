control 'SV-88637' do
  title 'The Cisco IOS XE router must use an authentication server for the purpose of granting administrative access.'
  desc "All accounts used for access to the network device are privileged or system-level accounts. Therefore, if account management functions are not automatically enforced, an attacker could gain privileged access to a vital element of the network security architecture.

The use of Authentication, Authorization, and Accounting (AAA) affords the best methods for controlling user access, authorization levels, and activity logging. By enabling AAA on the routers in conjunction with an authentication server such as TACACS+ or RADIUS, the administrators can easily add or remove user accounts, add or remove command authorizations, and maintain a log of user activity.

The use of an authentication server provides the capability to assign device administrators to tiered groups that contain their privilege level, which is used for authorization of specific commands. 

This control does not include emergency administration accounts that provide access to the network device components in case of network failure. There must be only one such locally defined account. All other accounts must be defined. All other accounts must be created and managed on the site's authentication server (e.g., RADIUS, LDAP, or Active Directory). This requirement is applicable to account management functions provided by the network device."
  desc 'check', 'Review the Cisco IOS XE router configuration to determine if there is an authentication server defined.

The configuration should look similar to the example below:

aaa new-model
aaa authentication login default group radius local
radius server RADIUS
  address ipv4 1.1.1.1
  key <pre-shared key>

If there is no authentication server defined, this is a finding.'
  desc 'fix', 'Configure the Cisco IOS XE router to use an authentication server.

The configuration should look similar to the example below:

aaa new-model
aaa authentication login default group radius local
radius server RADIUS
  address ipv4 1.1.1.1
  key <pre-shared key>'
  impact 0.7
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74045r5_chk'
  tag severity: 'high'
  tag gid: 'V-73963'
  tag rid: 'SV-88637r2_rule'
  tag stig_id: 'CISR-ND-000006'
  tag gtitle: 'SRG-APP-000023-NDM-000205'
  tag fix_id: 'F-80503r6_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
