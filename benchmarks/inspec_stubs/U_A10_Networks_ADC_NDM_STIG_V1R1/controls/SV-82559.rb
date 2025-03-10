control 'SV-82559' do
  title 'When anyone who has access to the emergency administration account no longer requires access to it or leaves the organization, the password for the emergency administration account must be changed.'
  desc "A shared/group account credential is a shared form of authentication that allows multiple individuals to access the network device using a single account. If shared/group account credentials are not terminated when individuals leave the group, the user that left the group can still gain access even though they are no longer authorized. There may also be instances when specific user actions need to be performed on the network device without unique administrator identification or authentication. Examples of credentials include passwords and group membership certificates.

Group accounts are not allowed except for the emergency administration account, which is an account can be created on the device's local database for use in an emergency, such as when the authentication server is down or connectivity between the device and the authentication server is not operable. This account is also referred to as the account of last resort since the emergency administration account is strictly intended to be used only as a last resort and immediate administrative access is absolutely necessary."
  desc 'check', 'Review the list of personnel who are authorized access to the emergency administration account and determine when someone either changed roles or left the organization. Compare this against the documented last change of the emergency administration account password. 

If the emergency administration account was not changed, this is a finding.'
  desc 'fix', 'When anyone who has access to the emergency administration account no longer requires access to it or leaves the organization, change the password for the emergency administration account.'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC NDM'
  tag check_id: 'C-68629r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68069'
  tag rid: 'SV-82559r1_rule'
  tag stig_id: 'AADC-NM-000085'
  tag gtitle: 'SRG-APP-000317-NDM-000282'
  tag fix_id: 'F-74185r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002142']
  tag nist: ['AC-2 (10)']
end
