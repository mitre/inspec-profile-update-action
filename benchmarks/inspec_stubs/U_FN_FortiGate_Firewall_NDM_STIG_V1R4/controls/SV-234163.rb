control 'SV-234163' do
  title 'The FortiGate device must automatically audit account modification.'
  desc 'Since the accounts in the network device are privileged or system-level accounts, account management is vital to the security of the network device. Account management by a designated authority ensures access to the network device is being controlled in a secure manner by granting access to only authorized personnel with the appropriate and necessary privileges. Auditing account modification, along with an automatic notification to appropriate individuals, will provide the necessary reconciliation that account management procedures are being followed. If modifications to management accounts are not audited, reconciliation of account management procedures cannot be tracked.'
  desc 'check', %q(If the System category of Event Logging is enabled, then account modification is audited. To check that Event and System Logging are enabled, log in to the FortiGate GUI with Super-Admin privilege.

1. Click Log and Report.
2. Click Log Settings.
3. Scroll down to Log Settings.
4. Verify Event Logging is set to "All" (for most verbose logging) or "Customize", and include at least the System activity event.

If Event Logging is not set to "All" or "Customize" with System enabled, then account modification is not audited, and this is a finding.

or

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:

     # show full-configuration log eventfilter | grep -i 'event\|system\|user'
The output should be:   
     set event enable
     set system enable
     set user enable

If event, system, and user parameters are set to disable, then account modification is not audited, and this is a finding.)
  desc 'fix', 'This fix can be performed on the FortiGate GUI or on the CLI. 
Log in to the FortiGate GUI with Super-Admin privilege.

1. Click Log and Report.
2. Click Log Settings.
3. Scroll down to Log Settings.
4. For Event Logging options, click "All" (for most verbose logging, or "Customize" and include at least the System activity event.
5. Click Apply.

or

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # config log eventfilter
     #    set event enable
     #    set system enable
     #    set user enable
     # end'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall NDM'
  tag check_id: 'C-37348r611676_chk'
  tag severity: 'medium'
  tag gid: 'V-234163'
  tag rid: 'SV-234163r879526_rule'
  tag stig_id: 'FGFW-ND-000010'
  tag gtitle: 'SRG-APP-000027-NDM-000209'
  tag fix_id: 'F-37313r611677_fix'
  tag 'documentable'
  tag cci: ['CCI-001403']
  tag nist: ['AC-2 (4)']
end
