control 'SV-242596' do
  title 'The Cisco ISE must be configured with a secondary log server in case the primary log is unreachable.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected.

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.'
  desc 'check', 'Review the configured Remote Logging Targets to ensure there are, at a minimum, two configured.
 
From the Web Admin portal:
1. Choose Administration >> System >> Logging >> Logging Targets.
2. Verify that "LogCollector" and "LogCollector2" or an additional target is defined along with being enabled.

If there are not two separate logging targets defined, this is a finding.

Note: "ProfilerRadiusProbe" or any other target with a "127.0.0.1" address does not count as being a "Remote" Logging Target.'
  desc 'fix', 'Configure Remote Logging Targets. 

From the Web Admin portal:
1. Choose Administration >> System >> Logging >> Logging Targets.
2. Select "Secure Syslog" or "TCP Syslog" in the Target Type drop-down.
3. Configure a desired name.
4. Configure the Host/IP address.
5. Check the box for "Buffer Messages When Server Down".
6. If "Secure Syslog" is used, select a CA certificate to use to define what system certificate to use to secure this connection.
7. Choose "Submit".

Note: "LogCollector" and "LogCollector2" represent the monitoring (MnT) nodes defined in the deployment. If there is a primary and a secondary MnT node, then nothing more is needed. 

Note: "ProfilerRadiusProbe" or any other target with a "127.0.0.1" address does not count as being a "Remote" Logging Target.'
  impact 0.5
  ref 'DPMS Target Cisco ISE NAC'
  tag check_id: 'C-45871r714096_chk'
  tag severity: 'medium'
  tag gid: 'V-242596'
  tag rid: 'SV-242596r714098_rule'
  tag stig_id: 'CSCO-NC-000220'
  tag gtitle: 'SRG-NET-000336-NAC-001390'
  tag fix_id: 'F-45828r714097_fix'
  tag 'documentable'
  tag cci: ['CCI-001861']
  tag nist: ['AU-5 (4)']
end
