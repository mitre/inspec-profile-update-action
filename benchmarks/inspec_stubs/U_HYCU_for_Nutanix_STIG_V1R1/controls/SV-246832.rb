control 'SV-246832' do
  title 'The HYCU server must generate audit records when successful/unsuccessful attempts to modify or delete administrator privileges occur.'
  desc 'This requirement addresses the configuration of network devices to mitigate the impact of DoS attacks that have occurred or are ongoing on device availability. For each network device, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or restricting the number of sessions the device opens at one time). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.

'
  desc 'check', 'Check the contents of the "/var/log/audit/audit.log" file.

HYCU also maintains Event (Audit) information in the "HYCU Web UI Events" menu. 

Verify the audit log contains records showing successful/unsuccessful attempts to modify or delete administrator privileges.

If the audit log is not configured or does not have required contents, this is a finding.'
  desc 'fix', 'Log on to the HYCU VM console and load the STIG audit rules by using the following commands:

1. cp /usr/share/doc/audit/rules/10-base-config.rules /usr/share/doc/audit/rules/30-stig.rules /usr/share/doc/audit/rules/31-privileged.rules /usr/share/doc/audit/rules/99-finalize.rules /etc/audit/rules.d/

2. augenrules --load'
  impact 0.5
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50264r768158_chk'
  tag severity: 'medium'
  tag gid: 'V-246832'
  tag rid: 'SV-246832r768160_rule'
  tag stig_id: 'HYCU-AU-000003'
  tag gtitle: 'SRG-APP-000495-NDM-000318'
  tag fix_id: 'F-50218r768159_fix'
  tag satisfies: ['SRG-APP-000495-NDM-000318', 'SRG-APP-000499-NDM-000319']
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
