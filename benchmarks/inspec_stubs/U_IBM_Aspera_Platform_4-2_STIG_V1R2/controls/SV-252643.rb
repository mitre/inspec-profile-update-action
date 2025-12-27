control 'SV-252643' do
  title 'The IBM Aspera High-Speed Transfer Server must restrict users from using transfer services by default.'
  desc 'Successful authentication must not automatically give an entity access to an asset or security boundary. The lack of authorization-based access control could result in the immediate compromise and unauthorized access to sensitive information. All DoD systems must be properly configured to incorporate access control methods that do not rely solely on authentication for authorized access.

Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization.

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. ALGs must use these policies and mechanisms to control access on behalf of the application for which it is acting as intermediary.

The IBM Aspera High Speed Transfer Server inherently uses file and group ownership of files and directories to support authorization for all supported operating systems. As an additional step and security best practice, ensure all transfers in or out of the authenticated connection are configured to be controlled based on privileges granted to specific users and groups within IBM Aspera configuration.'
  desc 'check', 'Verify the Aspera High-Speed Transfer Server restricts users from using transfer services by default with the following commands:

Check that the aspera.conf file is configured to deny transfer in and out by default.

$ sudo /opt/aspera/bin/asuserdata -a | grep authorization | grep value

authorization_transfer_in_value: "deny"
authorization_transfer_out_value: "deny"

If the results produce an "allow" value, this is a finding.'
  desc 'fix', 'Configure the Aspera High-Speed Transfer Server to restrict users from using transfer services by default with the following commands:

$ sudo /opt/aspera/bin/asconfigurator -x "set_node_data;authorization_transfer_in_value,deny"

$ sudo /opt/aspera/bin/asconfigurator -x "set_node_data;authorization_transfer_out_value,deny"

Restart the IBM Aspera Node service to activate the changes.

$ sudo systemctl restart asperanoded.service'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56099r818097_chk'
  tag severity: 'medium'
  tag gid: 'V-252643'
  tag rid: 'SV-252643r818099_rule'
  tag stig_id: 'ASP4-TS-020270'
  tag gtitle: 'SRG-NET-000015-ALG-000016'
  tag fix_id: 'F-56049r818098_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
