control 'SV-242618' do
  title 'For the local account of last resort, the Cisco ISE must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device.'
  desc 'Display of the DoD-approved use notification before granting access to the network device ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users, such as when directly logging in to the device.'
  desc 'check', 'Determine if the network device is configured to present a DoD-approved banner that is formatted in accordance with DTM-08-060.

In the configuration, view the "banner login" configuration.

If such a banner is not presented, this is a finding.'
  desc 'fix', 'Configure the administrative sessions login banner to display when users access the web or CLI interface that appears before and after an administrator logs in. By default, these login banners are disabled.

1. From the web management tool, click on Administration >> System >> Admin Access >> Settings >> Access >> Session.
2. To display the banner message before an administrator logs in, check the Pre-login banner check box and enter the message in the text box.
3. To display the banner message after an administrator logs in, check the Post-login banner check box and enter your message in the text box.
4. Click "Save".'
  impact 0.5
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45893r714162_chk'
  tag severity: 'medium'
  tag gid: 'V-242618'
  tag rid: 'SV-242618r879547_rule'
  tag stig_id: 'CSCO-NM-000120'
  tag gtitle: 'SRG-APP-000068-NDM-000215'
  tag fix_id: 'F-45850r714163_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
