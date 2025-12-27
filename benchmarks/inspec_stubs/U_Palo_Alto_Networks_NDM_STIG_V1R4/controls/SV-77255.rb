control 'SV-77255' do
  title 'The Palo Alto Networks security platform must only allow the use of secure protocols that implement cryptographic mechanisms to protect the integrity of maintenance and diagnostic communications for nonlocal maintenance sessions.'
  desc 'This requires the use of secure protocols instead of their unsecured counterparts, such as SSH instead of telnet, SCP instead of FTP, and HTTPS instead of HTTP. Note that HTTP OCSP is permitted to support OCSP where used. If unsecured protocols (lacking cryptographic mechanisms) are used for sessions, the contents of those sessions will be susceptible to manipulation, potentially allowing alteration and hijacking of maintenance sessions.'
  desc 'check', 'Go to Device >> Setup >> Management
In the "Management Interface Settings" window, view the enabled services.  
Note: Which management services are enabled.

If Telnet or HTTP is selected, this is a finding.'
  desc 'fix', 'Go to Device >> Setup >> Management.
In the "Management Interface Settings" window, select the "Edit" icon (the gear symbol in the upper-right corner).
In the "Management Interface Settings" window, make sure that Telnet or HTTP are not selected.
Select "OK".
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks Security Platform NDM'
  tag check_id: 'C-63573r3_chk'
  tag severity: 'medium'
  tag gid: 'V-62765'
  tag rid: 'SV-77255r2_rule'
  tag stig_id: 'PANW-NM-000117'
  tag gtitle: 'SRG-APP-000411-NDM-000330'
  tag fix_id: 'F-68685r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002890']
  tag nist: ['MA-4 (6)']
end
