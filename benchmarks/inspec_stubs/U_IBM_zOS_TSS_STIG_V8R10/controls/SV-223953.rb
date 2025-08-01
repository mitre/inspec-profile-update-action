control 'SV-223953' do
  title 'CA-TSS security administrator must develop a process to suspend userids found inactive for more than 35 days.'
  desc 'Inactive identifiers pose a risk to systems and applications because attackers may exploit an inactive identifier and potentially obtain undetected access to the system. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained.

Operating systems need to track periods of inactivity and disable application identifiers after 35 days of inactivity.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS LIST(ACIDS) 

If every user shows a LAST-USED=yy.ddd within the past "35" days, this is not a finding.

NOTE: VALID FOR INTERACTIVE USERIDS, NOT VALID FOR STARTED TASK USERIDS AND BATCH USERIDS.'
  desc 'fix', 'Develop a procedure to check all userids for inactivity of more than "35" days. If found, the ISSO must suspend an account, but not delete it until it is verified by the local ISSO that the user no longer requires access. If verification is not received within "60" days, the account may be deleted.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25626r516258_chk'
  tag severity: 'medium'
  tag gid: 'V-223953'
  tag rid: 'SV-223953r877794_rule'
  tag stig_id: 'TSS0-ES-000800'
  tag gtitle: 'SRG-OS-000118-GPOS-00060'
  tag fix_id: 'F-25614r516259_fix'
  tag 'documentable'
  tag legacy: ['V-98613', 'SV-107717']
  tag cci: ['CCI-000795']
  tag nist: ['IA-4 e']
end
