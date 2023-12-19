control 'SV-253805' do
  title "The Tanium endpoint must have the Tanium Server's pki.db in its installation."
  desc 'Without cryptographic integrity protections in the Tanium Client, information could be altered by unauthorized users without detection.

Cryptographic mechanisms used for protecting the integrity of Tanium communications information include signed hash functions using asymmetric cryptography, enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

'
  desc 'check', '1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web user interface (UI) and log on with multifactor authentication.

2. Click "Administration" on the top navigation banner.

3. Under "Configuration", select "Client Status".

4. Change "Show systems that have reported in the last:"; enter "7" in the first field. 

5. Select "Days" from the drop-down menu in the second field to determine if any endpoints connected with an invalid key.

If any systems are listed with "No" in the "Valid Key" column, this is a finding.'
  desc 'fix', 'For systems that do not have a valid key for the Tanium Server, redeploy the client software from Tanium using Tanium Client Management or work with the Tanium system administrator to accomplish this.

1. Configure a deployment.

2. Deploy the package or installer.

3. Target appropriate systems.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57257r842441_chk'
  tag severity: 'medium'
  tag gid: 'V-253805'
  tag rid: 'SV-253805r858416_rule'
  tag stig_id: 'TANS-CL-000001'
  tag gtitle: 'SRG-APP-000015'
  tag fix_id: 'F-57208r842442_fix'
  tag satisfies: ['SRG-APP-000158']
  tag 'documentable'
  tag cci: ['CCI-001453', 'CCI-000778']
  tag nist: ['AC-17 (2)', 'IA-3']
end
