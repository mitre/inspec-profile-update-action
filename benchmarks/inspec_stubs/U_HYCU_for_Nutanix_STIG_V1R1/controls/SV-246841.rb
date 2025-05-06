control 'SV-246841' do
  title 'The HYCU Web UI must generate an immediate real-time alert of all audit failure events requiring real-time alerts.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected.'
  desc 'check', 'Log on to the HYCU Web UI and review the Events menu and Email Notifications to verify that all appropriate/relevant audit failure events are included in the "Category" drop-down menu. 

If these events are not shown (reference a recent event capturing a login to HYCU for validation), this is a finding.'
  desc 'fix', 'Log on to the HYCU Web UI and go to the "Events" menu and open "Email Notifications".
 
Ensure that all the appropriate/relevant categories are selected and that the "Status" includes failures.
 
Add a "Subject" for the Email Notifications and email address for necessary auditors or HYCU administrators.'
  impact 0.5
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50273r768185_chk'
  tag severity: 'medium'
  tag gid: 'V-246841'
  tag rid: 'SV-246841r768187_rule'
  tag stig_id: 'HYCU-AU-000018'
  tag gtitle: 'SRG-APP-000360-NDM-000295'
  tag fix_id: 'F-50227r768186_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
