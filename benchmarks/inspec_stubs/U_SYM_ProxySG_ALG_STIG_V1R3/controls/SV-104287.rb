control 'SV-104287' do
  title 'Symantec ProxySG providing content filtering must be configured to integrate with a system-wide intrusion detection system.'
  desc 'Without coordinated reporting between separate devices, it is not possible to identify the true scale and possible target of an attack.

Integration of the ALG with a system-wide intrusion detection system supports continuous monitoring and incident response programs. This requirement applies to monitoring at internal boundaries using TLS gateways, web content filters, email gateways, and other types of ALGs.

ALGs can work as part of the network monitoring capabilities to off-load inspection functions from the external boundary IDPS by performing more granular content inspection of protocols at the upper layers of the OSI reference model.'
  desc 'check', 'Verify that the ProxySG is configured to log to an intrusion detection system.

1. Log on to the Web Management Console.
2. Browse to "Configuration" and click "Access Logging. Verify that "Enable Access Logging" is checked.
3. Click Logs >> Upload Client and verify that the Client Type parameters are set to send logs to the intrusion detection system.
4. Click Policy >> Visual Policy Manager >> Launch.

If Symantec ProxySG providing content filtering is not be configured to integrate with a system-wide intrusion detection system, this is a finding.'
  desc 'fix', 'Configure the ProxySG to log to an intrusion detection system.

1. Log on to the Web Management Console.
2. Browse to "Configuration" and click "Access Logging. Check the "Enable Access Logging" option.
3. Click Logs >> Upload Client and ensure that the Client Type parameters are set to send logs to the intrusion detection system.'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93519r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94333'
  tag rid: 'SV-104287r1_rule'
  tag stig_id: 'SYMP-AG-000600'
  tag gtitle: 'SRG-NET-000383-ALG-000135'
  tag fix_id: 'F-100449r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002656']
  tag nist: ['SI-4 (1)']
end
