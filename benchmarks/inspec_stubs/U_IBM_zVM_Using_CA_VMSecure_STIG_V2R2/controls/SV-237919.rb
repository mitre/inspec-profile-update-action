control 'SV-237919' do
  title 'The IBM z/VM Security Manager must provide a procedure to disable userIDs after 35 days of inactivity.'
  desc 'Inactive identifiers pose a risk to systems and applications because attackers may exploit an inactive identifier and potentially obtain undetected access to the system. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained.

Operating systems need to track periods of inactivity and disable application identifiers after 35 days of inactivity.'
  desc 'check', 'Examine the procedure for disabling user accounts.

If the procedure performs the following steps, this is not a finding.

- Monitors the time since last logon.
- Checks all userIDs for inactivity more than 35 days.
- If found, the ISSO must suspend an account, but not delete it until it is verified by the local ISSO that the user no longer requires access.
- If verification is not received within 60 days, the account may be deleted.'
  desc 'fix', 'Develop a procedure that includes the following steps:
- Monitors the time since last logon.
- Checks all userIDs for inactivity more than 35 days.
- If found, the ISSO must suspend an account, but not delete it until it is verified by the local ISSO that the user no longer requires access.
- If verification is not received within 60 days, the account may be deleted.'
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41129r649595_chk'
  tag severity: 'medium'
  tag gid: 'V-237919'
  tag rid: 'SV-237919r649597_rule'
  tag stig_id: 'IBMZ-VM-000650'
  tag gtitle: 'SRG-OS-000118-GPOS-00060'
  tag fix_id: 'F-41088r649596_fix'
  tag 'documentable'
  tag legacy: ['SV-93591', 'V-78885']
  tag cci: ['CCI-000795']
  tag nist: ['IA-4 e']
end
