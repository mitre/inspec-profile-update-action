control 'SV-221634' do
  title 'Splunk Enterprise must enforce a 60-day maximum password lifetime restriction for the account of last resort.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed at specific intervals. If the application does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the system and/or application passwords could be compromised.

This requirement does not include emergency administration accounts that are meant for access to the application in case of failure. These accounts are not required to have maximum password lifetime restrictions.

In most enterprise environments, this requirement is usually mitigated by a properly configured external authentication system, like LDAP. Splunk local authentication takes precedence over other forms of authentication, and cannot be disabled. The mitigation settings in this requirement apply in the event a local account gets created.'
  desc 'check', 'Select Settings >> Access Controls >> Password Policy Management and verify that Expiration is Enabled and Days until password expires is set to 60.

If not set this way, this is a finding.'
  desc 'fix', 'Select Settings >> Access Controls >> Password Policy Management and set Expiration to Enabled and Days until password expires to 60.'
  impact 0.3
  ref 'DPMS Target Splunk Enterprise 7.x for Windows'
  tag check_id: 'C-23349r416359_chk'
  tag severity: 'low'
  tag gid: 'V-221634'
  tag rid: 'SV-221634r879611_rule'
  tag stig_id: 'SPLK-CL-000380'
  tag gtitle: 'SRG-APP-000174-AU-002570'
  tag fix_id: 'F-23338r416360_fix'
  tag 'documentable'
  tag legacy: ['SV-111359', 'V-102415']
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
