control 'SV-228851' do
  title 'The Palo Alto Networks security platform must automatically update malicious code protection mechanisms.'
  desc 'Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include broadband and wireless connections. Remote access methods include, for example, proxied remote encrypted traffic (e.g., TLS gateways, web content filters, and webmail proxies).'
  desc 'check', 'Go to Device >> Dynamic Updates
If no entries for Applications and Threats are present, this is a finding.
If the Applications and Threats entry states Download Only, this is a finding.

This can be downgraded if a manual process is used.  If a manual process is used, compare the Applications and Threats database for the most recent version.
Go to Dashboard >> General Information, if the application, threat, and URL filtering definition versions are not the most current ones listed on the vendor support site, this is a finding.'
  desc 'fix', 'Go to Device >> Dynamic Updates; select "Check Now" at the bottom of the page to retrieve the latest signatures.
To schedule automatic signature updates.  Note: The steps provided below do not account for local change management policies.
Go to Device >> Dynamic Updates; select the text to the right of Schedule.
In the "Applications and Threat Updates Schedule" window; complete the required information.  
In the "Recurrence" field, select Daily.
In the "Time" field, enter the time at which you want the device to check for updates.
For the Action, select "Download and Install".   
Select "OK".
Commit changes by selecting "Commit" in the upper-right corner of the screen.  Select "OK" when the confirmation dialog appears.

If using Dynamic Updates is not possible due to mission requirements, implement a manual process.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31086r513848_chk'
  tag severity: 'medium'
  tag gid: 'V-228851'
  tag rid: 'SV-228851r557387_rule'
  tag stig_id: 'PANW-AG-000065'
  tag gtitle: 'SRG-NET-000251-ALG-000131'
  tag fix_id: 'F-31063r513849_fix'
  tag 'documentable'
  tag legacy: ['V-62583', 'SV-77073']
  tag cci: ['CCI-001247']
  tag nist: ['SI-3 (2)']
end
