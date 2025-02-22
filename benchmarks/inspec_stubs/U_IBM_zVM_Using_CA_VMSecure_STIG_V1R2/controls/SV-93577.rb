control 'SV-93577' do
  title 'CA VM:Secure product AUTOEXP record in the Security Config File must be properly set.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised.'
  desc 'check', 'Examine the “SECURITY CONFIG” file.

If there is no “AUTOEXP” record, this is a finding.

If the “AUTOEXP” record is configured as below, this is not finding.

AUTOEXP 50 60'
  desc 'fix', 'Include an “AUTOEXP” record in the “SECURITY CONFIG” file that is configured as follows:

AUTOEXP 50 60'
  impact 0.5
  ref 'DPMS Target z/VM Using CA VM:Secure'
  tag check_id: 'C-78457r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78871'
  tag rid: 'SV-93577r1_rule'
  tag stig_id: 'IBMZ-VM-000500'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-85621r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
