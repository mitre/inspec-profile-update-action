control 'SV-228658' do
  title 'The Palo Alto Networks security platform must terminate management sessions after 10 minutes of inactivity except to fulfill documented and validated mission requirements.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system-level network connection. This does not mean that the device terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.

Device management sessions are normally ended by the Administrator when he or she has completed the management activity.  The session termination takes place from the web client by selecting "Logout" (located at the bottom-left of the GUI window) or using the command line commands "exit" or "quit" at Operational mode.'
  desc 'check', 'Go to Device >> Setup >> Management.
View the "Authentication Settings" pane.
If the "Idle Timeout (min)" field is not "10" or less, ask the Administrator to produce documentation signed by the Authorizing Official that the configured value exists to support mission requirements.
If this documentation is not made available, this is a finding.'
  desc 'fix', 'Go to Device >> Setup >> Management.
In the "Authentication Settings" pane, select the "Edit" icon (the gear symbol in the upper-right corner of the pane).
In the "Idle Timeout (min)" field, enter "10", then select "OK".
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.7
  ref 'DPMS Target Palo Alto Networks NDM'
  tag check_id: 'C-30893r513577_chk'
  tag severity: 'high'
  tag gid: 'V-228658'
  tag rid: 'SV-228658r539622_rule'
  tag stig_id: 'PANW-NM-000069'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag fix_id: 'F-30870r513578_fix'
  tag 'documentable'
  tag legacy: ['SV-77233', 'V-62743']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
