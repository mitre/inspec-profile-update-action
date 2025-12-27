control 'SV-252623' do
  title 'The IBM Aspera High-Speed Transfer Endpoint must not store user content-protection secrets in plain text.'
  desc 'Configuring the network element to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the network element. Security-related parameters are those parameters impacting the security state of the network element, including the parameters required to satisfy other security control requirements. For the network element, security-related parameters include settings for network traffic management configurations.

Aspera recommends that you do not store content-protection secrets in aspera.conf.'
  desc 'check', 'Verify the IBM High-Speed Transfer Endpoint does not store user content-protection secrets in plain text.

For each user, run the following command:

Warning: If an invalid user/group name is entered, the asuserdata command will return results that may appear accurate. Ensure that the user/group name is valid and entered into the command correctly.

$ sudo /opt/aspera/bin/asuserdata -u <username> | grep secret | grep transfer

transfer_encryption_content_protection_secret: "AS_NULL"

If the "transfer_encryption_content_protection_secret" is not "AS_NULL", this is a finding.'
  desc 'fix', 'Configure the IBM High-Speed Transfer Endpoint to not store user content-protection secrets in plain text.

For each user, remove any secrets from the /opt/aspera/aspera.conf file with the following command:

$ sudo /opt/aspera/bin/asconfigurator -x "set_user_data; user_name,<name>; transfer_encryption_content_protection_secret,AS_NULL"
Restart the IBM Aspera Node service to activate the changes.

$ sudo systemctl restart asperanoded.service'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56079r818037_chk'
  tag severity: 'medium'
  tag gid: 'V-252623'
  tag rid: 'SV-252623r831523_rule'
  tag stig_id: 'ASP4-TE-030210'
  tag gtitle: 'SRG-NET-000512-ALG-000062'
  tag fix_id: 'F-56029r818038_fix'
  tag 'documentable'
  tag cci: ['CCI-002475', 'CCI-002476']
  tag nist: ['SC-28 (1)', 'SC-28 (1)']
end
