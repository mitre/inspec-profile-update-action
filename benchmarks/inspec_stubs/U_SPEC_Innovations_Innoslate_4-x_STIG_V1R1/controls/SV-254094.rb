control 'SV-254094' do
  title 'Innoslate must map the authenticated identity to the individual user or group account for PKI-based authentication.'
  desc 'Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.'
  desc 'check', 'Open the settings.properties file [Path] and  verify the AUTHENTICATION_TYPE is set to "CAC".

If AUTHENTICATION_TYPE is not set to "CAC", this is a finding.'
  desc 'fix', '1. Open the settings.properties file [Path].
2. Change the AUTHENTICATION_TYPE  to "CAC".
3. Save.
4. Restart the Innoslate service.'
  impact 0.7
  ref 'DPMS Target SPEC Innovations Innoslate 4.x'
  tag check_id: 'C-57579r845256_chk'
  tag severity: 'high'
  tag gid: 'V-254094'
  tag rid: 'SV-254094r845258_rule'
  tag stig_id: 'SPEC-IN-000390'
  tag gtitle: 'SRG-APP-000177'
  tag fix_id: 'F-57530r845257_fix'
  tag 'documentable'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
