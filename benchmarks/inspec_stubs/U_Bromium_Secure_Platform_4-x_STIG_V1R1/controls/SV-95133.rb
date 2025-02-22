control 'SV-95133' do
  title 'The Bromium Enterprise Controller (BEC) must generate a log record that can be sent to the central log server, which will alert the system administrator (SA) and Information System Security Officer (ISSO), at a minimum,  when a Bromium vSentry client has not connected to the BEC for logging or policy update purposes for an organization-defined time period.'
  desc 'It is critical for the appropriate personnel to be aware if an endpoint fails to connect to the management server within a defined time period. Without this notification, the security personnel may be unaware of an impending failure of the event capture capability, malicious activity, or insider threat.

Failure for a vSentry client to report in may be caused by network failures, unauthorized users escalating privileges to disable the security software, altering local hostname resolution settings, etc.'
  desc 'check', 'Verify that the reporting threshold for endpoints has been documented. 

Navigate to the management console, click on the selection arrow next to "Events".

Verify the organization-defined time period that the  vSentry client must connect to the BEC for logging or policy update purposes is configured.

If the BEC does not generate a log record  when a Bromium vSentry client has not connected to the BEC for logging or policy update purposes for an organization-defined time period, this is a finding.'
  desc 'fix', 'Define the organization-defined time period for when an alert should be generated.

Navigate to the management console, click on the selection arrow next to "Events" and verify the organization-defined time period that the  vSentry client must connect to the BEC for logging or policy update purposes is configured.'
  impact 0.5
  ref 'DPMS Target Bromium Secure Platform'
  tag check_id: 'C-80101r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80429'
  tag rid: 'SV-95133r1_rule'
  tag stig_id: 'BROM-00-000195'
  tag gtitle: 'SRG-APP-000108'
  tag fix_id: 'F-87235r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
