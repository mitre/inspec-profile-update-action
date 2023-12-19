control 'SV-250346' do
  title 'The WebSphere Liberty Server LTPA keys password must be changed.'
  desc 'The default location of the automatically generated Lightweight Third Party Authentication (LTPA) keys file is ${server.output.dir}/resources/security/ltpa.keys. 

The LTPA keys are encrypted with a randomly generated key and a default password of WebAS is initially used to protect the keys. The password is required when importing the LTPA keys into another server. To protect the security of the LTPA keys, change the password. 

When the LTPA keys are exchanged between servers, this password must match across the servers for Single Sign On (SSO) to work.

Automated LTPA key generation can create unplanned outages. Plan to change the LTPA keys during a scheduled outage and do not use automated key changes. Distribute the new keys to all nodes in the cell and to all external systems/cells during this outage window.'
  desc 'check', 'If LTPA is not used, this requirement is not a finding.

As a privileged user with access to ${server.config.dir}/server.xml file, review the server.xml file and locate LTPA settings. If the LTPA settings do not exist, this is not a finding.

EXAMPLE:
grep -i "<ltpa" server.xml

 <ltpa keysFileName="LTPA.keys" keysPassword="myLTPAkeysPassword" expiration="120" monitorInterval="5s" />

If the LTPA setting exists and the password is set to "WebAS", this is a finding.'
  desc 'fix', 'To update key password and force a regeneration of keys follow these steps. To obtain encoded values, use the Liberty "securityUtility encode" command.

1. Shut down the server.

2. Configure the <ltpa> element in the server.xml file as follows, replacing the sample values in the example with local values. The password may be encoded or encrypted.

<ltpa keysFileName="yourLTPAKeysFileName.keys" keysPassword="yourkeysPassword" expiration="120" />

3. Delete the existing ${wlp.server.dir}/resources/security/ltpa.keys file.

4. Sync changes with all servers in the cell.

5. Start the servers.'
  impact 0.5
  ref 'DPMS Target IBM WebSphere Liberty Server'
  tag check_id: 'C-53781r850904_chk'
  tag severity: 'medium'
  tag gid: 'V-250346'
  tag rid: 'SV-250346r850905_rule'
  tag stig_id: 'IBMW-LS-001050'
  tag gtitle: 'SRG-APP-000428-AS-000265'
  tag fix_id: 'F-53735r795090_fix'
  tag 'documentable'
  tag cci: ['CCI-002475']
  tag nist: ['SC-28 (1)']
end
