control 'SV-75299' do
  title 'The Arista Multilayer Switch must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device.'
  desc 'Display of the DoD-approved use notification before granting access to the network device ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users.'
  desc 'check', 'Review the device configuration and verify display of the Standard DoD Notice and Consent Banner.

If the banner is not displayed, this is a finding.

To verify the device is configured to display the DoD Banner, review the running configuration with the "show running-config" command. Identify the section "banner login" and verify the standard DoD Banner is displayed.'
  desc 'fix', 'Configure the switch to display the Standard DoD Notice and Consent banner.

To configure the banner, enter the following commands from the configuration mode interface. Replace the bracketed data with the DoD Banner.

switch(config)#banner login
[DoD Banner]
EOF'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series NDM'
  tag check_id: 'C-61789r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60843'
  tag rid: 'SV-75299r1_rule'
  tag stig_id: 'AMLS-NM-000160'
  tag gtitle: 'SRG-APP-000068-NDM-000215'
  tag fix_id: 'F-66553r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
