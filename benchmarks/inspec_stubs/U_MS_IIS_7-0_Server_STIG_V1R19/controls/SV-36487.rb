control 'SV-36487' do
  title 'The service account ID used to run the website must have its password changed at least annually.'
  desc 'Normally, a service account is established for the web service to run under rather than permitting it to run as system or root.  If the web service account requires a password, the password must be changed at least annually.  It is a fundamental tenet of security that passwords are not to be null and must not be set to never expire.'
  desc 'check', '1. Go to Start, Administrative Tools, and then Services.
2. Right-click on service name World Wide Web Publishing Service, Select Properties, and then select the Log On tab.
3. If “Local System account” is selected for the logon account, this is not a finding.  If the “This account” option is selected, the username given is the web service account ID.
 4. Open a command prompt and enter Net User [service account ID], press Enter.
5. Verify the values for Password last set and Password expires to ensure the password has been changed in the past year and will be required to change within the coming year.'
  desc 'fix', 'Configure the service account ID used to run the web-site to have its password changed at least annually, or use the local system account.'
  impact 0.5
  ref 'DPMS Target IIS Installation 7'
  tag check_id: 'C-38468r4_chk'
  tag severity: 'medium'
  tag gid: 'V-2235'
  tag rid: 'SV-36487r4_rule'
  tag stig_id: 'WG060 IIS7'
  tag gtitle: 'WG060'
  tag fix_id: 'F-27578r3_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', 'Web Administrator']
end
