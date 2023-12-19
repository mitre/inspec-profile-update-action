control 'SV-39317' do
  title 'The system, if capable, must be configured to require the use of a CAC, PIV compliant hardware token, or Alternate Logon Token (ALT) for authentication.'
  desc 'In accordance with CTO 07-015, PKI authentication is required. This provides stronger, two-factor authentication than using a username/password.

NOTE: The following are exempt from this; however, they must meet all password requirements and must be documented with the IAO:

- Stand-alone systems.
- Application Accounts.
- Students or unpaid employees (such as interns) who are not eligible to receive or not in receipt of a CAC, PIV, or ALT.
- Warfighters and support personnel located at operational tactical locations conducting wartime operations that are not “collocated” with RAPIDS workstations to issue CAC, are not eligible for CAC, or do not have the capability to use ALT.
- Test systems with an Interim Approval to Test (IATT) and provide protection via separate VPN, firewall, or security measures preventing access to network and system components from outside the protection boundary documented in the IATT.'
  desc 'check', 'Consult vendor documentation to determine if the system is capable of CAC authentication. If it is not, this is not applicable.

Interview the SA to determine if all accounts not exempted by policy are using CAC authentication. If non-exempt accounts are not using CAC authentication, this is a finding.'
  desc 'fix', 'Consult IBM documentation to determine the procedures necessary for configuring CAC authentication through PKI. Configure all accounts required by policy to use CAC authentication.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-30833r1_chk'
  tag severity: 'medium'
  tag gid: 'V-24347'
  tag rid: 'SV-39317r2_rule'
  tag stig_id: 'GEN009120'
  tag gtitle: 'GEN009120'
  tag fix_id: 'F-33551r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000768']
  tag nist: ['IA-2 (4)']
end
