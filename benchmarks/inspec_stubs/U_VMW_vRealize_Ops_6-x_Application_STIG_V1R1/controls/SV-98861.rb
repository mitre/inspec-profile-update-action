control 'SV-98861' do
  title 'The vRealize Operations server must only allow the use of DoD PKI-established certificate authorities for verification of the establishment of protected sessions.'
  desc 'Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DoD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DoD-approved CA, trust of this CA has not been established.

The DoD will only accept PKI certificates obtained from a DoD-approved internal or external certificate authority. Reliance on CAs for the establishment of secure sessions includes, for example, the use of SSL/TLS certificates.  The application server must only allow the use of DoD PKI-established certificate authorities for verification.'
  desc 'check', 'Verify that the vROps Single Sign-On (SSO) is configured with the correct authentication source only (DoD PKI CAC enabled vSphere SSO instance) by using the following steps:

1. Log on to the admin UI as the administrator.
2. In the menu, click Administration, and then in the left pane click Access >> Authentication Sources.
3. Review the authentication sources and ensure that only the DoD PKI CAC enabled vSphere SSO instance is available as an authentication source.

If there is no authentication source, or multiple non-DoD PKI CAC enabled vSphere SSO instance authentication sources exist, this is a finding.'
  desc 'fix', 'Configure vROps Single Sign-On (SSO) with the following steps:

1. Log on to vRealize Operations Manager as an administrator.
2. In the menu, click Administration, and then in the left pane click Access >> Authentication Sources.
3. Click "Add".
4. In the Add Source for User and Group Import dialog box, provide information for the single sign-on source.
5. Click "Test" to test the source connection.
6. Click "OK". The certificate details are displayed.
7. Select the "Accept this Certificate" check box.
8. Click "OK".
9. In the "Import User Groups" dialog box, import user accounts from an SSO server on another machine.
10. In the list of user groups displayed, select at least one user group.
11. Click "Next".
12. In the "Roles and Objects" pane, select a role from the "Select Role" drop-down menu.
13. Select the "Assign this role to the group" check box.
14. Select the "objects" users of the group can access when holding this role.

To assign permissions so that users can access all the objects in vRealize Operations Manager:

1. Select the "Allow access to all objects in the system" check box.
2. Click "OK".

Note: For complete details review vROps 6.x and vSphere SSO product documentation.'
  impact 0.5
  ref 'DPMS Target vRealize Operations Manager 6.x Application'
  tag check_id: 'C-87903r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88211'
  tag rid: 'SV-98861r1_rule'
  tag stig_id: 'VROM-AP-000540'
  tag gtitle: 'SRG-APP-000427-AS-000264'
  tag fix_id: 'F-94953r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
