control 'SRG-NET-000213-VVSM-00101_rule' do
  title 'The Unified Communications Session Manager must be configured to terminate all network connections associated with a communications session at the end of the session.'
  desc 'Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, and de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system level network connection.

Unified Communications Session Managers do not conduct media session; they conduct the session termination signaling. Endpoints and border elements conduct the media sessions and de-allocate those resources. However, sessions that do not receive a response from the far end may require the session manager to request termination of communication sessions.'
  desc 'check', 'Verify the Unified Communications Session Manager terminates all network connections associated with a communications session at the end of the session.

If the Unified Communications Session Manager does not terminate all network connections associated with a communications session at the end of the session, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Session Manager to terminate all network connections associated with a communications session at the end of the session.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000213-VVSM-00101_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000213-VVSM-00101'
  tag rid: 'SRG-NET-000213-VVSM-00101_rule'
  tag stig_id: 'SRG-NET-000213-VVSM-00101'
  tag gtitle: 'SRG-NET-000213-VVSM-00101'
  tag fix_id: 'F-SRG-NET-000213-VVSM-00101_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
