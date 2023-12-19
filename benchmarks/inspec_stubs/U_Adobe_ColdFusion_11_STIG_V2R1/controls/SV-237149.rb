control 'SV-237149' do
  title 'ColdFusion must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which logable events are to be logged.'
  desc 'ColdFusion utilizes role-based access controls in order to specify those individuals who are able to configure logable events.   Allowing users other than the ISSM and appointed individuals access to turn logged events on or off allows a user to mask their actions by disabling logging.  By enabling excessive logging or by enabling debugging, a user can generate logged events containing information that can be used to later attack the system or gain access to Personally Identifiable Information (PII).'
  desc 'check', 'Review the roles assigned to the defined users within the "User Manager" page under the "Security" menu.  Only the ISSM, or users appointed by the ISSM to change logable events, may have the following roles:
Debugging and Logging>Logging
Debugging and Logging>Code Analyzer
Debugging and Logging>Debugging
Debugging and Logging>License Scanner
Debugging and Logging>System Probes

If any other users have any of these roles, then this is a finding.'
  desc 'fix', 'Navigate to the "User Manager" page under the "Security" menu and assign the following roles to the ISSM and users appointed by the ISSM to change logable events.
Debugging and Logging>Logging
Debugging and Logging>Code Analyzer
Debugging and Logging>Debugging
Debugging and Logging>License Scanner
Debugging and Logging>System Probes'
  impact 0.5
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40368r641540_chk'
  tag severity: 'medium'
  tag gid: 'V-237149'
  tag rid: 'SV-237149r641542_rule'
  tag stig_id: 'CF11-02-000034'
  tag gtitle: 'SRG-APP-000090-AS-000051'
  tag fix_id: 'F-40331r641541_fix'
  tag 'documentable'
  tag legacy: ['SV-76861', 'V-62371']
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
