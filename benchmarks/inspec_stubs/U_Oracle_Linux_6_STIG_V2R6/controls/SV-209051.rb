control 'SV-209051' do
  title 'The system must be configured to require the use of a CAC, PIV compliant hardware token, or Alternate Logon Token (ALT) for authentication.'
  desc 'Smart card login provides two-factor authentication stronger than that provided by a username/password combination. Smart cards leverage a PKI (public key infrastructure) in order to provide and verify credentials.'
  desc 'check', 'Interview the SA to determine if all accounts not exempted by policy are using CAC authentication. For DoD systems, the following systems and accounts are exempt from using smart card (CAC) authentication: 

Standalone systems
Application accounts
Temporary employee accounts, such as students or interns, who cannot easily receive a CAC or PIV
Operational tactical locations that are not collocated with RAPIDS workstations to issue CAC or ALT
Test systems, such as those with an Interim Approval to Test (IATT) and use a separate VPN, firewall, or security measure preventing access to network and system components from outside the protection boundary documented in the IATT.

If non-exempt accounts are not using CAC authentication, this is a finding.'
  desc 'fix', 'To enable smart card authentication, consult the documentation at:

https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/6/html/Managing_Smart_Cards/enabling-smart-card-login.html

For guidance on enabling SSH to authenticate against a Common Access Card (CAC), consult documentation at:

https://access.redhat.com/solutions/82273'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9304r357938_chk'
  tag severity: 'medium'
  tag gid: 'V-209051'
  tag rid: 'SV-209051r793772_rule'
  tag stig_id: 'OL6-00-000349'
  tag gtitle: 'SRG-OS-000105'
  tag fix_id: 'F-9304r357939_fix'
  tag 'documentable'
  tag legacy: ['V-50639', 'SV-64845']
  tag cci: ['CCI-000765']
  tag nist: ['IA-2 (1)']
end
