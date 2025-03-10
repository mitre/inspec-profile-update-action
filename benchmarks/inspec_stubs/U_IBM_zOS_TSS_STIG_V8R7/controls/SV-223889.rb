control 'SV-223889' do
  title 'The CA-TSS PPEXP Control Option must be properly set.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS MODIFY STATUS

If the PPEXP Control Option will conform to the following requirements, this is not a finding.

PPEXP(60)'
  desc 'fix', 'Configure the PPEXP Control Option value to conform to the following requirements.

PPEXP(60)

Example:

TSS MODIFY PPEXP(60)'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25562r516066_chk'
  tag severity: 'medium'
  tag gid: 'V-223889'
  tag rid: 'SV-223889r561402_rule'
  tag stig_id: 'TSS0-ES-000160'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-25550r516067_fix'
  tag 'documentable'
  tag legacy: ['SV-107589', 'V-98485']
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
