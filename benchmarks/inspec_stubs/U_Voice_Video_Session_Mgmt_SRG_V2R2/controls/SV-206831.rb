control 'SV-206831' do
  title 'The Voice Video Session Manager must terminate all network connections associated with a communications session at the end of the session, or the session must be terminated after 15 minutes of inactivity.'
  desc 'Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, and de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system level network connection.

Voice Video Session Managers do not conduct media session; they conduct the session termination signaling. Endpoints and border elements conduct the media sessions and de-allocate those resources. However, sessions that do not receive a response from the far end may require the session manager to request termination of communication sessions.'
  desc 'check', 'Verify the Voice Video Session Manager terminates all network connections associated with a communications session at the end of the session, or the session terminates after 15 minutes of inactivity.

If the Voice Video Session Manager does not terminate all network connections associated with a communications session at the end of the session, this is a finding.

If the Voice Video Session Manager does not terminate the session after 15 minutes of inactivity, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager to terminate all network connections associated with a communications session at the end of the session. Alternatively, configure the Voice Video Session Manager to terminate the session after 15 minutes of inactivity.'
  impact 0.7
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7086r459024_chk'
  tag severity: 'high'
  tag gid: 'V-206831'
  tag rid: 'SV-206831r508661_rule'
  tag stig_id: 'SRG-NET-000213-VVSM-00011'
  tag gtitle: 'SRG-NET-000213'
  tag fix_id: 'F-7086r459025_fix'
  tag 'documentable'
  tag legacy: ['SV-76587', 'V-62097']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
