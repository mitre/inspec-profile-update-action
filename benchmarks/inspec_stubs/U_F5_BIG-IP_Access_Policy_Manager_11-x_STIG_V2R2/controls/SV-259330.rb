control 'SV-259330' do
  title 'F5 BIG-IP must be configured to set a "Maximum Session Timeout" value of 24 hours or less.'
  desc "The Maximum Session Timeout setting configures a limit on the maximum amount of time a user's session is active without needing to reauthenticate. If the value is set to 0 (zero), the user's session is active until either the user terminates the session or the Inactivity Timeout value is reached (the default value is set to 604,800 seconds). When determining how long the maximum user session can last, it may be useful to review the access policy. For example, if the access policy requires that the user's antivirus signatures cannot be older than 24 hours, the Maximum Session Timeout should not exceed that time limit."
  desc 'check', 'If the BIG-IP APM module does not provide user authentication intermediary services, this is not applicable.

Navigate to the BIG-IP System manager >> Access Policy >> Access Profiles.

Click "Edit..." in the "Access Policy" column for Access Profiles used for granting access.

In the "Settings" section, view the value for "Maximum Session Timeout".

If the F5 BIG-IP APM module is not configured for a "Maximum Session Timeout" value of 86,400 seconds or less, this is a finding.'
  desc 'fix', 'BIG-IP LTM controls the timeout values of sessions in the definition of an access profile. 

Navigate to the BIG-IP System manager >> Access Policy >> Access Profiles.

Click "Edit..." in the "Access Policy" column for Access Profiles used for granting access.

In the "Settings" section, set the value for "Maximum Session Timeout" to 86,400 seconds or less (24 hours or less).'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Access Policy Manager 11.x'
  tag check_id: 'C-63069r939141_chk'
  tag severity: 'medium'
  tag gid: 'V-259330'
  tag rid: 'SV-259330r939148_rule'
  tag stig_id: 'F5BI-AP-000230'
  tag gtitle: 'SRG-NET-000337-ALG-000096'
  tag fix_id: 'F-62978r939142_fix'
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
