control 'SV-89669' do
  title 'The MQ Appliance network device must compare internal information system clocks at least every 24 hours with an authoritative time server.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside of the configured acceptable allowance (drift) may be inaccurate. Additionally, unnecessary synchronization may have an adverse impact on system performance and may indicate malicious activity. Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.'
  desc 'check', 'Log on to the MQ Appliance WebGUI as a privileged user. 

On the Manage Appliance tab, select Network >> Interface/NTP Service. 

Verify: 
- NTP server destinations are configured; 
- The NTP servers are located in different geographic regions; and 
- Status (at the top of the page) is "up". 

If any is not true, this is a finding.'
  desc 'fix', 'Log on to the MQ Appliance WebGUI as a privileged user. 

Click on the Network icon (third from the top). 
Select "Interface/NTP Service". 
Click the "Add" button to add multiple NTP servers. 
Click "Enable administrative state". 
Click the "Apply" button. 

Add one or more additional NTP servers, at least one of which is from a different geographic region. 

The result should be: "Status:up" 

Click "Save configuration".'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 NDM'
  tag check_id: 'C-74847r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74995'
  tag rid: 'SV-89669r1_rule'
  tag stig_id: 'MQMH-ND-001060'
  tag gtitle: 'SRG-APP-000371-NDM-000296'
  tag fix_id: 'F-81611r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end
