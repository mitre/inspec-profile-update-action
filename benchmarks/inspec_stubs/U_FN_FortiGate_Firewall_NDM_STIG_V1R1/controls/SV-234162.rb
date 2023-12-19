control 'SV-234162' do
  title 'The FortiGate device must automatically audit account creation.'
  desc 'Upon gaining access to a network device, an attacker will often first attempt to create a persistent method of reestablishing access. One way to accomplish this is to create a new account. Notification of account creation helps to mitigate this risk. Auditing account creation provides the necessary reconciliation that account management procedures are being followed. Without this audit trail, personnel without the proper authorization may gain access to critical network nodes.'
  desc 'check', %q(If the System category of Event Logging is enabled, then account creation is audited. To check that System and Event Logging are enabled, log in to the FortiGate GUI with Super-Admin privilege.

1. Click Log and Report.
2. Click Log Settings.
3. Scroll down to Log Settings.
4. Verify Event Logging is set to "All" (for most verbose logging) or "Customize", and includes at least the System activity event.

If Event Logging is not set to "All" or "Customize" with System enabled, then account creation will not be audited, and this is a finding.

or 

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:

     # show full-configuration log eventfilter | grep -i 'event\|system'
The output should be: 
     set event enable
     set system enable

If event and system parameters are set to disable, the account creation is not audited, and this is a finding.)
  desc 'fix', 'This fix can be performed on the FortiGate GUI or on the CLI. 
Log in to the FortiGate GUI with Super-Admin privilege.

1. Click Log and Report.
2. Click Log Settings.
3. Scroll down to Log Settings.
4. For Event Logging options, click "All" (for most verbose logging) or "Customize", and include at least the System activity event.
5. Click Apply.

or

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # config log eventfilter
     #    set event enable
     #    set system enable
     #    set endpoint enable
     #    set user enable
     # end'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate NDM'
  tag check_id: 'C-37347r611673_chk'
  tag severity: 'medium'
  tag gid: 'V-234162'
  tag rid: 'SV-234162r628777_rule'
  tag stig_id: 'FGFW-ND-000005'
  tag gtitle: 'SRG-APP-000026-NDM-000208'
  tag fix_id: 'F-37312r611674_fix'
  tag 'documentable'
  tag cci: ['CCI-000018']
  tag nist: ['AC-2 (4)']
end
