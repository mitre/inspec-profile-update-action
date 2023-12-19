control 'SV-258601' do
  title 'The ICS must be configured to audit the execution of privileged functions such as accounts additions and changes.'
  desc 'Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.

'
  desc 'check', 'In the ICS Web UI, navigate to System >> Log/Monitoring >> Admin Access >> Settings, under the section "Select Events to Log".

If Administrator changes is enabled for events logging, this is a finding.'
  desc 'fix', 'Enable logging for admin event actions.

In the ICS Web UI, navigate to System >> Log/Monitoring >> Admin Access >> Settings.
1. Check the box for Administrator changes under the section "Select Events to Log".
2. Click "Save Changes".'
  impact 0.5
  ref 'DPMS Target Ivanti Connect Secure NDM'
  tag check_id: 'C-62341r930489_chk'
  tag severity: 'medium'
  tag gid: 'V-258601'
  tag rid: 'SV-258601r930491_rule'
  tag stig_id: 'IVCS-NM-000060'
  tag gtitle: 'SRG-APP-000343-NDM-000289'
  tag fix_id: 'F-62250r930490_fix'
  tag satisfies: ['SRG-APP-000343-NDM-000289', 'SRG-APP-000495-NDM-000318', 'SRG-APP-000499-NDM-000319', 'SRG-APP-000503-NDM-000320', 'SRG-APP-000504-NDM-000321', 'SRG-APP-000505-NDM-000322', 'SRG-APP-000506-NDM-000323', 'SRG-APP-000319-NDM-000283', 'SRG-APP-000381-NDM-000305', 'SRG-APP-000100-NDM-000230', 'SRG-APP-000029-NDM-000211', 'SRG-APP-000028-NDM-000210', 'SRG-APP-000027-NDM-000209', 'SRG-APP-000038-NDM-000213', 'SRG-APP-000099-NDM-000229', 'SRG-APP-000098-NDM-000228', 'SRG-APP-000097-NDM-000227', 'SRG-APP-000096-NDM-000226', 'SRG-APP-000095-NDM-000225', 'SRG-APP-000026-NDM-000208', 'SRG-APP-000412-NDM-000331', 'SRG-APP-000411-NDM-000330', 'SRG-APP-000435-NDM-000315', 'SRG-APP-000156-NDM-000250', 'SRG-APP-000224-NDM-000270', 'SRG-APP-000179-NDM-000265', 'SRG-APP-000142-NDM-000245']
  tag 'documentable'
  tag cci: ['CCI-000018', 'CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000172', 'CCI-000382', 'CCI-000803', 'CCI-001188', 'CCI-001368', 'CCI-001403', 'CCI-001404', 'CCI-001405', 'CCI-001487', 'CCI-001814', 'CCI-001941', 'CCI-002130', 'CCI-002234', 'CCI-002385', 'CCI-002890', 'CCI-003123']
  tag nist: ['AC-2 (4)', 'AU-3 a', 'AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-12 c', 'CM-7 b', 'IA-7', 'SC-23 (3)', 'AC-4', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AU-3 f', 'CM-5 (1)', 'IA-2 (8)', 'AC-2 (4)', 'AC-6 (9)', 'SC-5 a', 'MA-4 (6)', 'MA-4 (6)']
end
