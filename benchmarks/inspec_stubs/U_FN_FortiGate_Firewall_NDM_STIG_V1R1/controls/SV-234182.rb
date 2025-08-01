control 'SV-234182' do
  title 'The FortiGate device must generate an immediate real-time alert of all audit failure events requiring real-time alerts.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected.

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click Security Fabric.
2. Click Automation.
3. Verify Automation Stitches are configured to send alerts related to audit processing failure.
4. For each Automation Stitch, verify a valid Action Email has been configured.

If Automation Stitches are not defined to trigger an immediate real-time alert of all audit processing failures, this is a finding.

Note: Relevant events for an Automation Stitch are below:

Disk Full
Disk Log access failed
Disk log directory deleted
Disk log file deleted 
Disk log full over first warning
Disk logs failed to back up
Disk logs failed to back up to USB
Disk partitioning or formatting Error
Disk unavailable
FortiAnalyzer connection down
FortiAnalyzer connection failed
FortiAnalyzer is not configured for Security Fabric service
FortiAnalyzer log access failed
Log disk failure imminent
Log disk full
Log disk unavailable
Memory log access failed
Memory log full over final warning level
Memory log full over first warning level
Memory log full over second warning level
Memory logs failed to back up'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click Security Fabric.
2. Click Automation.
3. Click +Create New (Automation Stitch).
4. Assign a meaningful name.
5. For Trigger, select FortiOS Event Log.
6. For Event field, Click + (and choose a specific event type).
7. For Action, select Email, specify recipients, and Email subject.
8. Click OK.

Note: The following are all relevant Event Log entries. For most complete coverage, configure an Automation Stitch for each of the Event Log entries below:

Disk Full
Disk Log access failed
Disk log directory deleted
Disk log file deleted 
Disk log full over first warning
Disk logs failed to back up
Disk logs failed to back up to USB
Disk partitioning or formatting Error
Disk unavailable
FortiAnalyzer connection down
FortiAnalyzer connection failed
FortiAnalyzer is not configured for Security Fabric service
FortiAnalyzer log access failed
Log disk failure imminent
Log disk full
Log disk unavailable
Memory log access failed
Memory log full over final warning level
Memory log full over first warning level
Memory log full over second warning level
Memory logs failed to back up'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate NDM'
  tag check_id: 'C-37367r611733_chk'
  tag severity: 'medium'
  tag gid: 'V-234182'
  tag rid: 'SV-234182r628777_rule'
  tag stig_id: 'FGFW-ND-000115'
  tag gtitle: 'SRG-APP-000360-NDM-000295'
  tag fix_id: 'F-37332r611734_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
