control 'SV-250987' do
  title 'MobileIron Sentry must display the Standard Mandatory DoD Notice and Consent Banner in the Sentry web interface before granting access to the device.'
  desc 'Display of the DoD-approved use notification before granting access to the network device ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users.'
  desc 'check', %q(Verify that MobileIron Sentry displays "I've read and consent to terms in IS user agreem't" when logging in to the command line.

1. Log in to the Sentry System Manager or the CLI interface.
2. Verify the required login banner is displayed.

If the banner is not shown, this is a finding.)
  desc 'fix', %q(Configure MobileIron Sentry to display "I've read and consent to terms in IS user agreem't" when logging in to the command line.

1. Log in to the Sentry System Manager.
2. Go to Settings >> Login.
3. Add the required login banner to the "Text to Display" box.
4. Click "Apply".)
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x NDM'
  tag check_id: 'C-54422r802181_chk'
  tag severity: 'medium'
  tag gid: 'V-250987'
  tag rid: 'SV-250987r802183_rule'
  tag stig_id: 'MOIS-ND-000150'
  tag gtitle: 'SRG-APP-000068-NDM-000215'
  tag fix_id: 'F-54376r802182_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
