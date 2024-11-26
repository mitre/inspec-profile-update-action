control 'SV-251007' do
  title 'MobileIron Sentry must be running an operating system release that is currently supported by MobileIron.'
  desc 'Network devices running an unsupported operating system lack current security fixes required to mitigate the risks associated with recent vulnerabilities.'
  desc 'check', 'Verify the MobileIron Sentry is a supported version. 

1. Enter the MobileIron Sentry System Manager Portal URL in a web browser.
2. View the version number in the top right corner.
3. Check the MI Support page (help.mobileiron.com) to ensure the MI Sentry is a supported version. 

If the version number of the Sentry appliance is not supported, this is a finding.'
  desc 'fix', 'Install the most current MobileIron supported version of Sentry.'
  impact 0.7
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x NDM'
  tag check_id: 'C-54442r802241_chk'
  tag severity: 'high'
  tag gid: 'V-251007'
  tag rid: 'SV-251007r802243_rule'
  tag stig_id: 'MOIS-ND-000990'
  tag gtitle: 'SRG-APP-000516-NDM-000351'
  tag fix_id: 'F-54396r802242_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
