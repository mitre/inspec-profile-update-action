control 'SV-233329' do
  title 'Forescout must configure TCP for the syslog protocol to allow for detection by the central event server if communications is lost. This is required for compliance with C2C Step 1.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected.

Note that this configuration allows for the central log server to be configured with a critical alert to be sent to the System Security Officer (ISSO) and Systems Administrator (SA) (at a minimum) if it is unable to communicate the Forescout or stops receiving log updates. The alert requirement is in the Syslog STIG.'
  desc 'check', 'If DoD is not at C2C Step 1 or higher, this is not a finding.

1. Go to Tools >> Options >> Syslog.
2. Verify the Server Protocol is set to TCP.
3. Verify "Use TLS" setting is set.
4. Verify the "Identity, Facility, and Severity" setting is configured.

If Forescout does not use TCP for the syslog protocol, this is a finding.'
  desc 'fix', 'Configure Syslog server with TCP, as well as configure Syslog to alert if the communication between the Syslog server and the Forescout appliance loses connectivity.

1. Go to Tools >> Options >> Syslog.
2. Click Add/Edit.
3. Configure the Syslog:
- Syslog Server IP address
- Server Port
- Server Protocol set to TCP
- Check the Use TLS setting
- Configure the Identity, Facility, and Severity.
4. Click "OK".
5. Click "Apply".'
  impact 0.5
  ref 'DPMS Target Forescout Network Access Control'
  tag check_id: 'C-36524r811407_chk'
  tag severity: 'medium'
  tag gid: 'V-233329'
  tag rid: 'SV-233329r811408_rule'
  tag stig_id: 'FORE-NC-000230'
  tag gtitle: 'SRG-NET-000088-NAC-000440'
  tag fix_id: 'F-36489r605691_fix'
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
