control 'SV-250985' do
  title 'MobileIron Sentry must enforce approved authorizations for controlling the flow of management information within the network device based on information flow control policies.'
  desc 'A mechanism to detect and prevent unauthorized communication flow must be configured or provided as part of the system design. If management information flow is not enforced based on approved authorizations, the network device may become compromised. Information flow control regulates where management information is allowed to travel within a network device. The flow of all management information must be monitored and controlled so it does not introduce any unacceptable risk to the network device or data. 

Application-specific examples of enforcement occur in systems that employ rule sets or establish configuration settings that restrict information system services or message-filtering capability based on message content (e.g., implementing key word searches or using document characteristics).

Applications providing information flow control must be able to enforce approved authorizations for controlling the flow of management information within the system in accordance with applicable policy.'
  desc 'check', 'Review MobileIron Sentry configuration to determine if it enforces approved authorizations for controlling the flow of management information within the network.

Sentry receives a request from MobileIron Core and enforces verification before handling the request to validate that it is from a trusted MobileIron Core.

Therefore, if the deployment uses MobileIron Core, to verify that Sentry trusts MobileIron Core in the deployment:

1. Run the following command in MobileIron Sentry CLI:
show sentry EMM-source-verify 

If this is set to "false", this is a finding.

2. Run the following command in MobileIron Sentry CLI:
show sentry emm-ips 

If the Core IP is not specified, this is a finding.

3. Verify MobileIron Sentry has an ACL for Core in MobileIron Sentry System Manager.

Then:
1. In the Standalone Sentry System Manager, go to Security >> Access Control Lists.
2. Verify that an ACL is created for Core. If it is not, this is a finding.
3. Determine if MobileIron Sentry is configured with specified backend services such as Exchange Active Sync or App Tunnels.

If the backend service is not specified, this is a finding. 

Refer to section "Configuring Standalone Sentry for ActiveSync" and "Configuring Standalone Sentry for AppTunnel" in "MobileIron Sentry 9.8 Guide for MobileIron Core" to ensure these services are configured in MobileIron Sentry settings in Core where applicable.'
  desc 'fix', 'Configure MobileIron Sentry to enforce approved authorizations for controlling the flow of management information within the network device. 

Sentry receives a request from MobileIron Core and enforces verification before handling the request to validate that it is from a trusted MobileIron Core.

Therefore, if the deployment uses MobileIron Core, to ensure that Sentry trusts MobileIron Core in the deployment, run the following commands in MobileIron Sentry CLI:

1. sentry emm-source-verify true

2. sentry emm-ips <subnet_list>>

3. This can further be mitigated by creating ACLs for MobileIron Sentry System Manager.

Then:
1. In the Standalone Sentry System Manager, go to Security >> Access Control Lists.
2. Click "Add".
3. In the "Name" field, enter a name to identify the ACL.
4. In the "Description" field, enter text to clarify the purpose of the ACL.
5. Click "Save".
6. Select the new ACL that was created and click it, which should open a Modify ACL dialog box.
7. Click "Add" to add an access control entry (ACE) to the ACL.
Each ACE consists of a combination of the network hosts and services that were configured for use in ACLs.
8. Use the following guidelines to complete the form:
Source Network 
Destination Network
Service
Action - Select Permit or Deny from the dropdown list.
Connections Per Minute
9. Click "Save".
10. Configure Sentry with specified backend services such as Exchange Active Sync or App Tunnels. Refer to section "Configuring Standalone Sentry for ActiveSync" and "Configuring Standalone Sentry for AppTunnel" in "MobileIron Sentry 9.8 Guide for MobileIron Core" to ensure these services are configured in MobileIron Sentry settings in Core where applicable.'
  impact 0.3
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x NDM'
  tag check_id: 'C-54420r802175_chk'
  tag severity: 'low'
  tag gid: 'V-250985'
  tag rid: 'SV-250985r802177_rule'
  tag stig_id: 'MOIS-ND-000130'
  tag gtitle: 'SRG-APP-000038-NDM-000213'
  tag fix_id: 'F-54374r802176_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
