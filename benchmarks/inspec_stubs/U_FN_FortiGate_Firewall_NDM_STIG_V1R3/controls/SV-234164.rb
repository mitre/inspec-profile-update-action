control 'SV-234164' do
  title 'The FortiGate device must automatically audit account removal actions.'
  desc 'Account management, as a whole, ensures access to the network device is being controlled in a secure manner by granting access to only authorized personnel. Auditing account removal actions will support account management procedures. When device management accounts are terminated, user or service accessibility may be affected. Auditing also ensures authorized active accounts remain enabled and available for use when required.'
  desc 'check', %q(If the System category of Event Logging is enabled, then account removal is audited. To check that System and Event Logging is configured, log in to the FortiGate GUI with Super-Admin privilege.

1. Click Log and Report.
2. Click Log Settings.
3. Scroll down to Log Settings.
4. Verify Event Logging is set to "All" (for most verbose logging) or "Customize" and include at least the System activity event.

If the Event Logging is not set to "All" or "Customize" with System enabled, then account removal is not audited, and this is a finding.

or 

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:

     # show full-configuration log eventfilter | grep -i 'event\|system'
The output should be:   
     set event enable
     set system enable

If event and system parameters are set to disable, then account removal is not audited, and this is a finding.)
  desc 'fix', 'This fix can be performed on the FortiGate GUI or on the CLI. 
Log in to the FortiGate GUI with Super-Admin privilege.

1. Click Log and Report.
2. Click Log Settings.
3. Scroll down to Log Settings.
4. For Event Logging options, click "All" (for most verbose logging) or "Customize" and include at least System activity event.
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
  ref 'DPMS Target Fortinet FortiGate Firewall NDM'
  tag check_id: 'C-37349r611679_chk'
  tag severity: 'medium'
  tag gid: 'V-234164'
  tag rid: 'SV-234164r611681_rule'
  tag stig_id: 'FGFW-ND-000020'
  tag gtitle: 'SRG-APP-000029-NDM-000211'
  tag fix_id: 'F-37314r611680_fix'
  tag 'documentable'
  tag cci: ['CCI-001405']
  tag nist: ['AC-2 (4)']
end
