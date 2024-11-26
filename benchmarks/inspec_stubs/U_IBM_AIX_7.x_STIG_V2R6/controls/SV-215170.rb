control 'SV-215170' do
  title 'AIX must automatically remove or disable temporary user accounts after 72 hours or sooner.'
  desc 'If temporary user accounts remain active when no longer needed or for an excessive period, these accounts may be used to gain unauthorized access. To mitigate this risk, automated termination of all temporary accounts must be set upon account creation.

Temporary accounts are established as part of normal account activation procedures when there is a need for short-term accounts without the demand for immediacy in account activation.

If temporary accounts are used, the operating system must be configured to automatically terminate these types of accounts after a DoD-defined time period of 72 hours.

To address access requirements, many operating systems may be integrated with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'From the command prompt, execute the following command:
# lsuser -a expires tmp_user

The above command should yield the following output:
tmp_user expires=0
Or
tmp_user expires=1215103116

The "expires" value is in "MMDDhhmmyy" form, or the value is "0".

If "expires" value is "0", or the expiration time is greater than "72" hours from the user creation time, this is a finding.'
  desc 'fix', 'From the command prompt, execute the following command to set the expiration time to 72 hours from now:
# chuser expires=1218103116 tmp_user

From the command prompt, execute the following command:
# lsuser -a expires tmp_user

The above command should yield the following output:
tmp_user expires=1218103116'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16368r293961_chk'
  tag severity: 'medium'
  tag gid: 'V-215170'
  tag rid: 'SV-215170r508663_rule'
  tag stig_id: 'AIX7-00-001001'
  tag gtitle: 'SRG-OS-000002-GPOS-00002'
  tag fix_id: 'F-16366r293962_fix'
  tag 'documentable'
  tag legacy: ['SV-101317', 'V-91217']
  tag cci: ['CCI-000016']
  tag nist: ['AC-2 (2)']
end
