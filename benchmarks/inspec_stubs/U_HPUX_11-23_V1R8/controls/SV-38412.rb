control 'SV-38412' do
  title 'The system, if capable, must be configured to require the use of a CAC, PIV compliant hardware token or Alternate Logon Token (ALT) for authentication.'
  desc 'In accordance with CTO 07-015 PKI authentication is required. This provides stronger, two-factor authentication than using a username/password.

NOTE: The following are exempt from this; however, they must meet all password requirements and must be documented with the IAO:

- Stand-alone systems.
- Application Accounts.
- Students or unpaid employees (such as interns) who are not eligible to receive or not in receipt of a CAC, PIV, or ALT.
- Warfighters and support personnel located at operational tactical locations conducting wartime operations that are not “collocated” with RAPIDS workstations to issue CAC; are not eligible for CAC or do not have the capability to use ALT.
- Test systems that have an Interim Approval to Test (IATT) and provide protection via separate VPN, firewall or security measures preventing access to network and system components from outside the protection boundary documented in the IATT.'
  desc 'check', 'Example: 
Reflection PKI Services Manager is a separate add-on providing X.509 certificate authentication services for the following Attachmate products: Reflection for Secure IT UNIX Server (7.1 or higher), and Reflection for Secure IT UNIX Client (7.1 or higher). The following HP-UX systems are supported by Reflection PKI Services Manager 1.0 or higher:
HP-UX 11i v3 (Itanium) 
HP-UX 11i v2 (Itanium) 
HP-UX 11i v2 (PA-RISC) 
HP-UX 11i v1 (PA-RISC)

To determine if the system is capable of CAC authentication, ask the SA if the system uses the Reflection PKI Services Manager for the Attachmate product (or similar). If it is not, this is not applicable.

Additionally, ask the SA to determine if all accounts not exempted by policy are using CAC authentication. If non-exempt accounts are not using CAC authentication, this is a finding.'
  desc 'fix', 'Consult vendor and/or 3rd party documentation to determine the procedures necessary for configuring CAC authentication. Configure all accounts required by policy to use CAC authentication to use CAC authentication.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36803r1_chk'
  tag severity: 'medium'
  tag gid: 'V-24347'
  tag rid: 'SV-38412r2_rule'
  tag stig_id: 'GEN009120'
  tag gtitle: 'GEN009120'
  tag fix_id: 'F-32181r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-2, IAIA-1'
  tag cci: ['CCI-000768']
  tag nist: ['IA-2 (4)']
end
