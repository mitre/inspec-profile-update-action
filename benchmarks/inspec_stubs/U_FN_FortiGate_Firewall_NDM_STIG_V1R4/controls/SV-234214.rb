control 'SV-234214' do
  title 'The FortiGate device must terminate idle sessions after 10 minutes of inactivity.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system-level network connection. This does not mean that the device terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click System.
2. Click Settings.
3. Go to Administrative Settings.
4. Verify Idle Timeout is configured to 10 minutes.

If the idle-timeout value is not 10 minutes, this is a finding.

or 

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # show full-configuration sys global | grep -i admintimeout

The output should be:         
          set admintimeout 10

If the admintimeout parameter is not set to 10 minutes, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click System.
2. Click Settings.
3. Go to Administrative Settings.
4. Enter the Idle Timeout value of 10.
5. Click Apply.

or 

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # config system global
          # set admintimeout 10
     # end'
  impact 0.7
  ref 'DPMS Target Fortinet FortiGate Firewall NDM'
  tag check_id: 'C-37399r611829_chk'
  tag severity: 'high'
  tag gid: 'V-234214'
  tag rid: 'SV-234214r916342_rule'
  tag stig_id: 'FGFW-ND-000275'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag fix_id: 'F-37364r611830_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
