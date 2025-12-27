control 'SV-256079' do
  title 'The Riverbed NetProfiler must be configured to authenticate each administrator prior to authorizing privileges based on roles.'
  desc 'The lack of role-based access control could result in the immediate compromise of and unauthorized access to sensitive information. Additionally, without mapping the PKI certificate to a unique user account, the ability to determine the identities of individuals or assert nonrepudiation is lost.

Individual accountability mandates that each administrator is uniquely identified. For public key infrastructure (PKI)-based authentication, the device must be configured to map validated certificates to unique user accounts.

This requirement applies to accounts or roles created and managed on or by the network device.

'
  desc 'check', "Review the site's System Security Plan (SSP) to determine which personnel are assigned to each NetProfiler role. 

Go to Administration >> Account Management >> User Accounts. 

Go to the Roles-Attributes Mapping section of the RADIUS, TACACS+, or SAML tab of the Configuration >> Account Management >> Remote Authentication page. 

If account roles are not configured, or if the roles assigned do not match the site's SSP, this is a finding."
  desc 'fix', %q(Although all individual admin accounts must be configured on an authentication server, the NetProfiler must be configured to point to a PKI-based authentication server and the NetProfiler roles must be mapped to the authorization attributes on the authentication server.

The following is an example using RADIUS. Refer to the user's guide for instructions for TACACS+ or SAML. 

Users who do not have a NetProfiler or NetExpress account must have both their authentication information (login name, password) and authorization information (user role indicated by the value of the Class attribute or the Cascade-User-Role attribute) specified on the RADIUS server. The values of the RADIUS authorization attributes must be mapped to their corresponding user roles on NetProfiler or NetExpress.

The values on the RADIUS server and the values on NetProfiler or NetExpress must match for the user to be logged on. To map the NetProfiler or NetExpress user roles to RADIUS authorization attributes:

1. Click "Edit" in the Roles-Attributes Mapping section of the RADIUS tab of the Configuration >> Account Management >> Remote Authentication page. 
2. For the first user role, click "Add new attribute" to display an edit box.
3. Select the RADIUS authorization attribute (Class or Cascade-User-Role). (If assigning the Restricted user account role, use the Restricted-Filter attribute to limit the account to traffic specified by traffic expressions. Refer to the in-product help system for additional information about Restricted user accounts.)
4. Enter the value of the attribute that is required for a RADIUS-authorized user to be logged on in this user role.
5. If applicable, click "Add new attribute" to add another mapping.
6. Continue with the next user role that is to be authorized by RADIUS.
7. When the RADIUS authorization attributes have been mapped to their corresponding NetProfiler user roles, click "Save".)
  impact 0.7
  ref 'DPMS Target Riverbed NetProfiler'
  tag check_id: 'C-59753r882743_chk'
  tag severity: 'high'
  tag gid: 'V-256079'
  tag rid: 'SV-256079r882745_rule'
  tag stig_id: 'RINP-DM-000029'
  tag gtitle: 'SRG-APP-000153-NDM-000249'
  tag fix_id: 'F-59696r882744_fix'
  tag satisfies: ['SRG-APP-000153-NDM-000249', 'SRG-APP-000119-NDM-000236', 'SRG-APP-000120-NDM-000237', 'SRG-APP-000121-NDM-000238', 'SRG-APP-000122-NDM-000239', 'SRG-APP-000123-NDM-000240', 'SRG-APP-000329-NDM-000287', 'SRG-APP-000177-NDM-000263', 'SRG-APP-000033-NDM-000212']
  tag 'documentable'
  tag cci: ['CCI-000163', 'CCI-000164', 'CCI-000166', 'CCI-000187', 'CCI-000213', 'CCI-000366', 'CCI-000370', 'CCI-000764', 'CCI-000770', 'CCI-001493', 'CCI-001494', 'CCI-001495', 'CCI-002169']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-10', 'IA-5 (2) (a) (2)', 'AC-3', 'CM-6 b', 'CM-6 (1)', 'IA-2', 'IA-2 (5)', 'AU-9 a', 'AU-9', 'AU-9', 'AC-3 (7)']
end
