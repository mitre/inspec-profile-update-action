control 'SV-242235' do
  title 'The TippingPoint SMS, TPS, and SMS client must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device.'
  desc 'Display of the DoD-approved use notification before granting access to the network device ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users.

Configure banner messages to display security notices on the SMS client toolbar or when a user attempts to log in to the following interfaces: SMS client, SMS web management console, CLI, or remote SSH client. When configured, the notice and Consent Banner on the screen until the administrator acknowledges the usage conditions and takes explicit actions to log on for further access, as required by CCI-000050.

'
  desc 'check', 'Determine if the network device is configured to present a DoD-approved banner that is formatted in accordance with DTM-08-060.

Verify the SMS client has a login banner configured by viewing the SMS client toolbar, client login, web login, console/CLI, or remote/SSH login. 

Verify the TPS login banner is enabled: 
1. Click Devices, All Devices, and the TPS Device hostname. 
2. Click Device Configuration. 
3. Click Login Banner.

If the TippingPoint SMS, TPS, and SMS client does not display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device, this is a finding.'
  desc 'fix', 'Configure banner message to display on the SMS client toolbar or when a user attempts to log in to the following interfaces: SMS client, SMS web management console, CLI, or remote SSH client.

1. Select Edit >> Preferences >> Banner Message.
2. Check "Enable Banner Message".
3. Add the exactly worded and formatted DoD-approved banner as presented in accordance with DTM-08-060.
4. Check all the boxes under the banner to display on check display on client toolbar, client login, web login, console/CLI, and remote/SSH login. 

To enable the TPS login banner: 
1. Select Devices >> All Devices >> <TPS Device hostname>.
2. Select Device Configuration >> Login Banner >> Enable Banner Message.
3. Add the exactly worded and formatted DoD-approved banner as presented in accordance with DTM-08-060.
4. Click OK.'
  impact 0.3
  ref 'DPMS Target Trend Micro TippingPoint NDM'
  tag check_id: 'C-45510r710710_chk'
  tag severity: 'low'
  tag gid: 'V-242235'
  tag rid: 'SV-242235r710712_rule'
  tag stig_id: 'TIPP-NM-000050'
  tag gtitle: 'SRG-APP-000068-NDM-000215'
  tag fix_id: 'F-45468r710711_fix'
  tag satisfies: ['SRG-APP-000068-NDM-000215', 'SRG-APP-000069-NDM-000216']
  tag 'documentable'
  tag cci: ['CCI-000048', 'CCI-000050']
  tag nist: ['AC-8 a', 'AC-8 b']
end
