control 'SV-202017' do
  title 'The network device must be configured to assign appropriate user roles or access levels to authenticated users.'
  desc 'Successful identification and authentication must not automatically give an entity full access to a network device or security domain. The lack of authorization-based access control could result in the immediate compromise and unauthorized access to sensitive information. All DoD systems must be properly configured to incorporate access control methods that do not rely solely on authentication for authorized access.

Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset or set of resources. Information systems use access control policies and enforcement mechanisms to implement this requirement. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization.

Some network devices are pre-configured with security groups. Other network devices enable operators to create custom security groups with custom permissions. For example, an ISSM may require read-only access to audit the network device. Operators may create an audit security group, define permissions and access levels for members of the group, and then assign the ISSM’s user persona to the audit security group. This is still considered privileged access, but the ISSM’s security group is more restrictive than the network administrator’s security group.

Network devices that rely on AAA brokers for authentication and authorization services may need to identify the available security groups or access levels available on the network devices and convey that information to the AAA operator. Once the AAA broker identifies the user persona on the centralized directory service, the user’s security group memberships can be retrieved. The AAA operator may need to create a mapping that links target security groups from the directory service to the appropriate security groups or access levels on the network device. Once these mappings are configured, authorizations can happen dynamically, based on each user’s directory service group membership.'
  desc 'check', 'If the network device is configured to use a AAA service account, and the AAA broker is configured to assign authorization levels based on centralized user account group memberships on behalf of the network device, that will satisfy this objective. Because the responsibility for meeting this objective is transferred to the AAA broker, this requirement is not applicable for the local network device. This requirement may be verified by demonstration or configuration review.

Verify the network device is configured to assign appropriate user roles or access levels to authenticated users. This requirement may be verified by demonstration or configuration review. If the network device does not enforce the assigned privilege level for each administrator and authorizations for access to all commands relative to the privilege level, this is a finding.'
  desc 'fix', 'Configure the network device to assign appropriate user roles or access levels to authenticated users, or configure the network device to leverage an AAA solution that will satisfy this objective.'
  impact 0.7
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2143r663931_chk'
  tag severity: 'high'
  tag gid: 'V-202017'
  tag rid: 'SV-202017r663933_rule'
  tag stig_id: 'SRG-APP-000033-NDM-000212'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-2144r663932_fix'
  tag 'documentable'
  tag legacy: ['SV-69297', 'V-55051']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
