control 'SV-242259' do
  title 'The TippingPoint SMS must automatically generate audit records for account changes and actions with containing information needed for analysis of the event that occurred on the SMS and TPS.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information. 

Auditing account changes provides the necessary reconciliation that account management procedures are being followed. Without this audit trail, personnel without the proper authorization may gain access to critical network nodes.

Associating event types, date/time of the event,  identity of any individual or process associated with the event, source/destination of the event,  location of the event, and the outcome of the event provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured network device.

'
  desc 'check', 'In the SMS client, ensure the remote system is configured to generate all audit records. 

1. Navigate to Admin >> Server properties >> Syslog. 
2. Verify the configuration enables TCP.
3. Verify Device Audit, Device System, SMS Audit, and SMS System log types are enabled and configured.

If syslog is not configured to use TCP or does not include the four log types, this is a finding.'
  desc 'fix', 'In the SMS client, ensure the remote system is configured to generate all audit records. 

1. Navigate to Admin >> Server properties >> Syslog >> New.
2. Click enable.
3. Click TCP (required for DoD).
4. Under Log Type, select "Device Audit".
5. Facility is "Log Audit".
6. Timestamp: SMS Current Time.
7. Check "Include SMS hostname in Header".
8. Click OK.
9. Repeat these steps for the following three other Log Types: Device System, SMS Audit, and SMS System.'
  impact 0.7
  ref 'DPMS Target Trend Micro TippingPoint NDM'
  tag check_id: 'C-45534r710782_chk'
  tag severity: 'high'
  tag gid: 'V-242259'
  tag rid: 'SV-242259r754443_rule'
  tag stig_id: 'TIPP-NM-000670'
  tag gtitle: 'SRG-APP-000026-NDM-000208'
  tag fix_id: 'F-45492r710783_fix'
  tag satisfies: ['SRG-APP-000026-NDM-000208', 'SRG-APP-000027-NDM-000209', 'SRG-APP-000028-NDM-000210', 'SRG-APP-000029-NDM-000211', 'SRG-APP-000319-NDM-000283', 'SRG-APP-000091-NDM-000223', 'SRG-APP-000095-NDM-000225', 'SRG-APP-000096-NDM-000226', 'SRG-APP-000097-NDM-000227', 'SRG-APP-000099-NDM-000229', 'SRG-APP-000100-NDM-000230', 'SRG-APP-000100-NDM-000231', 'SRG-APP-000100-NDM-000289', 'SRG-APP-000100-NDM-000305', 'SRG-APP-000100-NDM-000318', 'SRG-APP-000100-NDM-000319', 'SRG-APP-000100-NDM-000321', 'SRG-APP-000100-NDM-000325', 'SRG-APP-000100-NDM-000334', 'SRG-APP-000100-NDM-000250']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001403', 'CCI-001404', 'CCI-001487', 'CCI-000018', 'CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000134', 'CCI-000135', 'CCI-000169', 'CCI-000172', 'CCI-001814', 'CCI-001851', 'CCI-002234', 'CCI-002605', 'CCI-002130']
  tag nist: ['CM-6 b', 'AC-2 (4)', 'AC-2 (4)', 'AU-3 f', 'AC-2 (4)', 'AU-3 a', 'AU-3 b', 'AU-3 c', 'AU-3 e', 'AU-3 (1)', 'AU-12 a', 'AU-12 c', 'CM-5 (1)', 'AU-4 (1)', 'AC-6 (9)', 'SI-2 c', 'AC-2 (4)']
end
