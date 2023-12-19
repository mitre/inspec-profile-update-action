control 'SV-203643' do
  title 'The operating system must use multifactor authentication for local access to non-privileged accounts.'
  desc 'To assure accountability, prevent unauthenticated access, and prevent misuse of the system, non-privileged users must utilize multifactor authentication for local access.

Multifactor authentication is defined as using two or more factors to achieve authentication.

Factors include: 
1) Something you know (e.g., password/PIN); 
2) Something you have (e.g., cryptographic identification device or token); and
3) Something you are (e.g., biometric).

A non-privileged account is defined as an operating system account with authorizations of a regular or non-privileged user.

Local access is defined as access to an organizational information system by a user (or process acting on behalf of a user) communicating through a direct connection without the use of a network.

The DoD CAC with DoD-approved PKI is an example of multifactor authentication.'
  desc 'check', 'Verify the operating system uses multifactor authentication for local access to non-privileged accounts. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to use multifactor authentication for local access to non-privileged accounts.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3768r557174_chk'
  tag severity: 'medium'
  tag gid: 'V-203643'
  tag rid: 'SV-203643r557176_rule'
  tag stig_id: 'SRG-OS-000108-GPOS-00055'
  tag gtitle: 'SRG-OS-000108'
  tag fix_id: 'F-3768r557175_fix'
  tag 'documentable'
  tag legacy: ['V-56761', 'SV-71021']
  tag cci: ['CCI-000768']
  tag nist: ['IA-2 (4)']
end
