control 'SV-223888' do
  title 'The CA-TSS PWEXP Control Option must be set to 60.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS MODIFY STATUS

If the PWEXP Control Option value is not set to PWEXP(60), this is a finding.'
  desc 'fix', 'Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the following control option setting as specified and proceed with the change.

PWEXP(60)'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25561r516063_chk'
  tag severity: 'medium'
  tag gid: 'V-223888'
  tag rid: 'SV-223888r877729_rule'
  tag stig_id: 'TSS0-ES-000150'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-25549r516064_fix'
  tag 'documentable'
  tag legacy: ['SV-107587', 'V-98483']
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
