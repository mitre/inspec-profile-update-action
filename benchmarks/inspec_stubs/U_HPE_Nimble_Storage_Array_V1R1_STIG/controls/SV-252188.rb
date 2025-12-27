control 'SV-252188' do
  title 'The HPE Nimble must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device.'
  desc 'Display of the DoD-approved use notification before granting access to the network device ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users.'
  desc 'check', 'Attempt a login to NimOS by typing "ssh username@array", where username is a valid user, and array is an array DNS name. If the correct DoD banner is not displayed before a password prompt, this is a finding.'
  desc 'fix', 'Type "group --edit --login_banner", and then copy-paste or type the required banner. Then, to display the banner before login, type "group --edit --login_banner_after_auth no".'
  impact 0.5
  ref 'DPMS Target HPE Nimble Storage Array'
  tag check_id: 'C-55644r814042_chk'
  tag severity: 'medium'
  tag gid: 'V-252188'
  tag rid: 'SV-252188r814044_rule'
  tag stig_id: 'HPEN-NM-000030'
  tag gtitle: 'SRG-APP-000068-NDM-000215'
  tag fix_id: 'F-55594r814043_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
