control 'SV-91671' do
  title 'The DBN-6300 must terminate all network connections associated with a device management session at the end of the session, or the session must be terminated after 10 minutes of inactivity except to fulfill documented and validated mission requirements.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, deallocating associated TCP/IP address/port pairs at the operating system level or deallocating networking assignments at the application level if multiple application sessions are using a single, operating system-level network connection. This does not mean that the device terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'Verify administrator accounts are configured with a 10-minute timeout setting.

Navigate to Settings >> Users.

Click on the wrench for an existing user.

View each user defined on the device since there is no setting for a global value.

If a timeout value of "600" is not set for each administrator account configured on the device, this is a finding.'
  desc 'fix', 'Configure administrator accounts with a timeout setting.

Navigate to Settings >> Users.

Click on the wrench for an existing user.

In the "Edit User" popup box, enter a timeout value of "600".

Click on "Commit".'
  impact 0.7
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-76601r1_chk'
  tag severity: 'high'
  tag gid: 'V-76975'
  tag rid: 'SV-91671r1_rule'
  tag stig_id: 'DBNW-DM-000071'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag fix_id: 'F-83671r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
