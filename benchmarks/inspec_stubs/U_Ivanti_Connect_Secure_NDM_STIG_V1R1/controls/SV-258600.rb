control 'SV-258600' do
  title 'The ICS must be configured to prevent nonprivileged users from executing privileged functions.'
  desc 'Preventing nonprivileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.

Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Nonprivileged users are individuals that do not possess appropriate authorizations.

'
  desc 'check', %q(Verify Realms and Roles are configured as needed to meet mission requirements.

In the ICS Web UI, navigate to Administrators >> Admin Realms >> Admin Realms.
1. Click the admin realm that is currently being used on the ICS for administrator logins. By default, it is "Admin Users".
2. In the "General" tab, under Servers >> Directory/Attribute, verify it does not say "none".
3. In the "Role Mapping" tab, under "when users meet these conditions", verify the following:
- "Group" must be used, and the local site's administrator active directory group must be selected and assigned to the ".Administrators" role. Note that this role could be different if using something other than the default ".Administrators" role.
- Verify separate usernames are not used. Verify an allow-all username of * is used.

If a realm or role is not configured to prevent nonprivileged users from executing privileged functions, this is a finding.)
  desc 'fix', 'Configure Realms and Roles as needed to meet mission requirements.

Note: The ".Administrators" role is a default role name, other administrator role names can be used. Groups must be used, separate usernames or an allow-all username of * is not acceptable.

In the ICS Web UI, navigate to Administrators >> Admin Realms >> Admin Realms.
1. Click the admin realm that is currently being used on the ICS for administrator logins. By default, it is "Admin Users".
2. In the "General" tab, under Servers >> Directory/Attribute, select the previously configured LDAP Directory. If none is configured, follow vendor supplied instructions for creating an LDAP Authentication Server.
3. In the "Role Mapping" tab, under "when users meet these conditions", select new rule.
4. Under rule based on, select "Group Membership".
5. Give the rule a name.
6. Select "is".
7. Provide the exact group name in the text box. This name must match the "CN=" attribute name. For example, if the group is "CN=ivanti.adm.group" then add the "ivanti.adm.group" to the text box.
8. Under "then assign these roles", select the admin role used by ICS for admin logins. By default this is ".Administrators".
9. Click "Save Changes".
10. Under "Role Mapping", if there are more roles needed for more specific role-based access to the ICS, configure more of them here. 
11. Once complete, click "Save Changes".'
  impact 0.7
  ref 'DPMS Target Ivanti Connect Secure NDM'
  tag check_id: 'C-62340r930486_chk'
  tag severity: 'high'
  tag gid: 'V-258600'
  tag rid: 'SV-258600r930488_rule'
  tag stig_id: 'IVCS-NM-000050'
  tag gtitle: 'SRG-APP-000340-NDM-000288'
  tag fix_id: 'F-62249r930487_fix'
  tag satisfies: ['SRG-APP-000340-NDM-000288', 'SRG-APP-000380-NDM-000304', 'SRG-APP-000378-NDM-000302', 'SRG-APP-000133-NDM-000244', 'SRG-APP-000123-NDM-000240', 'SRG-APP-000121-NDM-000238', 'SRG-APP-000231-NDM-000271', 'SRG-APP-000408-NDM-000314', 'SRG-APP-000329-NDM-000287', 'SRG-APP-000153-NDM-000249', 'SRG-APP-000119-NDM-000236', 'SRG-APP-000120-NDM-000237', 'SRG-APP-000033-NDM-000212', 'SRG-APP-000516-NDM-000335', 'SRG-APP-000516-NDM-000336', 'SRG-APP-000177-NDM-000263', 'SRG-APP-000080-NDM-000220']
  tag 'documentable'
  tag cci: ['CCI-000163', 'CCI-000164', 'CCI-000166', 'CCI-000187', 'CCI-000213', 'CCI-000345', 'CCI-000366', 'CCI-000370', 'CCI-000764', 'CCI-000770', 'CCI-001199', 'CCI-001493', 'CCI-001495', 'CCI-001499', 'CCI-001812', 'CCI-001813', 'CCI-002169', 'CCI-002235', 'CCI-002883']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-10', 'IA-5 (2) (a) (2)', 'AC-3', 'CM-5', 'CM-6 b', 'CM-6 (1)', 'IA-2', 'IA-2 (5)', 'SC-28', 'AU-9 a', 'AU-9', 'CM-5 (6)', 'CM-11 (2)', 'CM-5 (1) (a)', 'AC-3 (7)', 'AC-6 (10)', 'MA-3 (4)']
end
