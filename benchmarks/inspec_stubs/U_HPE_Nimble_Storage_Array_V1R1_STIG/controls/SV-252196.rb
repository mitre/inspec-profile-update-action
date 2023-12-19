control 'SV-252196' do
  title 'The HPE Nimble must terminate all network connections associated with a device management session at the end of the session, or the session must be terminated after 10 minutes of inactivity.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system-level network connection. This does not mean that the device terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'Type "group --info | grep inactivity" and review the timeout value. If it is greater than 10 minutes, this is a finding.'
  desc 'fix', 'To set the inactivity timeout to 10 minutes, type "group --edit --inactivity_timeout 10".'
  impact 0.7
  ref 'DPMS Target HPE Nimble Storage Array'
  tag check_id: 'C-55652r814066_chk'
  tag severity: 'high'
  tag gid: 'V-252196'
  tag rid: 'SV-252196r814068_rule'
  tag stig_id: 'HPEN-NM-000110'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag fix_id: 'F-55602r814067_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
