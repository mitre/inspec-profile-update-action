control 'SV-225625' do
  title 'Production WebSphere MQ Remotes must utilize Certified Name Filters (CNF)'
  desc 'IBM Websphere MQ can use a user ID associated with an ACP certificate as a channel user ID.  When an entity at one end of an SSL channel receives a certificate from a remote connection, the entity asks The ACP if there is a user ID associated with that certificate. The entity uses that user ID as the channel user ID. If there is no user ID associated with the certificate, the entity uses the user ID under which the channel initiator is running.  Without a validly defined Certificate Name Filter for the entity IBM Websphere MQ will set the channel user ID to the default.'
  desc 'check', 'Validate that the list of all Production WebSphere MQ Remotes exist, and contains approved Certified Name Filters and associated USERIDS.

If the filter(s) is (are) defined, accurate and has been approved by Vulnerability ICER0030 and the associated USERID(s) is only granted need to know permissions and authority to resources and commands, this is not a finding. 

If there is no Certificate Name Filter for WebSphere MQ Remotes this is a Finding.

Note: Improper use of CNF filters for MQ Series will result in the following Message ID.

CSQX632I found in the following example:

CSQX632I csect-name SSL certificate has no
associated user ID, remote channel
channel-name – channel initiator user ID
used'
  desc 'fix', 'The responsible MQ System programmer(s) shall create and maintain a spread sheet that contains a list of all Production WebSphere MQ Remotes, associated individual USERIDs with corresponding valid Certified Name Filters (CNF). This documentation will be reviewed and validated annually by responsible MQ System programmer(s) and forwarded for approval by the ISSM.

The ISSO will define the associated USERIDs, the CNF, and grant the minimal need to know access, by granting only the required resources and Commands for each USERID in the ACP. See IBM WebSphere MQ Security manual for details on defining CNF for WebSphere MQ.

Generic access shall not be granted such as resource permission at the SSID. MQ resource level.'
  impact 0.5
  ref 'DPMS Target zOS WebsphereMQ for TSS'
  tag check_id: 'C-27326r472677_chk'
  tag severity: 'medium'
  tag gid: 'V-225625'
  tag rid: 'SV-225625r472679_rule'
  tag stig_id: 'ZWMQ0014'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-27314r472678_fix'
  tag 'documentable'
  tag legacy: ['SV-41848', 'V-31561']
  tag cci: ['CCI-000366', 'CCI-001133']
  tag nist: ['CM-6 b', 'SC-10']
end
