control 'SV-3012' do
  title 'Network devices must be password protected.'
  desc "Network access control mechanisms interoperate to prevent unauthorized access and to enforce the organization's security policy. Access to the network must be categorized as administrator, user, or guest so the appropriate authorization can be assigned to the user requesting access to the network or a network device. Authorization requires an individual account identifier that has been approved, assigned, and configured on an authentication server. Authentication of user identities is accomplished through the use of passwords, tokens, biometrics, or in the case of multi-factor authentication, some combination thereof. Lack of authentication enables anyone to gain access to the network or possibly a network device providing opportunity for intruders to compromise resources within the network infrastructure."
  desc 'check', "Review the network devices configuration to determine if administrative access to the device requires some form of authentication--at a minimum a password is required.

If passwords aren't used to administrative access to the device, this is a finding."
  desc 'fix', 'Configure the network devices so it will require a password to gain administrative access to the device.'
  impact 0.7
  ref 'DPMS Target WLAN Controller'
  tag check_id: 'C-3456r6_chk'
  tag severity: 'high'
  tag gid: 'V-3012'
  tag rid: 'SV-3012r4_rule'
  tag stig_id: 'NET0230'
  tag gtitle: 'Network element is not password protected.'
  tag fix_id: 'F-3037r6_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
