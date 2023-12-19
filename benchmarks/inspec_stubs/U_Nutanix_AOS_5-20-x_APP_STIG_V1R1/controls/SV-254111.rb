control 'SV-254111' do
  title 'Nutanix AOS must accept Personal Identity Verification (PIV) credentials to access the management interface.'
  desc 'The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.

PIV credentials are only used in an unclassified environment.

DoD has mandated the use of the CAC to support identity management and personal authentication for systems covered under HSPD 12, as well as its use as a primary component of layered protection for national security systems.

The application server must support the use of PIV credentials to access the management interface and perform management functions.

'
  desc 'check', 'Confirm Nutanix AOS is set to use multifactor authentication.

1. Log in to Prism Element.
2. Click on the gear icon in the upper right.
3. Navigate to the Authentication settings.

If CAC authentication is not enabled, this is a finding.'
  desc 'fix', 'Configure Nutanix AOS Prism Elements to use CAC authentication.

1. Log in to Prism Elements.
2. Click on the gear icon in the upper right.
3. Navigate to the Authentication settings.
4. Select the "Configure Service Account" check box, and then complete the following in the indicated fields:
    a. Select the authentication directory that contains the CAC users to be authenticated. This list includes the directories configured on the Directory List tab.
    b. Service Username: Enter the username in the user name@domain.com format that the web console will use to log in to the Active Directory.
    c. Service Password: Enter the password for the service user name.
    d. Click "Enable CAC".'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x Application'
  tag check_id: 'C-57596r858124_chk'
  tag severity: 'medium'
  tag gid: 'V-254111'
  tag rid: 'SV-254111r858402_rule'
  tag stig_id: 'NUTX-AP-000290'
  tag gtitle: 'SRG-APP-000391-AS-000239'
  tag fix_id: 'F-57547r858402_fix'
  tag satisfies: ['SRG-APP-000391-AS-000239', 'SRG-APP-000392-AS-000240', 'SRG-APP-000177-AS-000126', 'SRG-APP-000401-AS-000243', 'SRG-APP-000402-AS-000247', 'SRG-APP-000403-AS-000248']
  tag 'documentable'
  tag cci: ['CCI-000187', 'CCI-001953', 'CCI-001954', 'CCI-001991', 'CCI-002009', 'CCI-002010']
  tag nist: ['IA-5 (2) (a) (2)', 'IA-2 (12)', 'IA-2 (12)', 'IA-5 (2) (d)', 'IA-8 (1)', 'IA-8 (1)']
end
