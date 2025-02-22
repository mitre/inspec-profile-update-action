control 'SV-91649' do
  title 'The DBN-6300 must use multifactor authentication for network access (remote and nonlocal) to privileged accounts.'
  desc 'Multifactor authentication requires using two or more factors to achieve authentication. Factors include: 

(i) something a user knows (e.g., password/PIN); 
(ii) something a user has (e.g., cryptographic identification device, token); or 
(iii) something a user is (e.g., biometric). 

Network access is defined as access to an information system by a user (or a process acting on behalf of a user) communicating through a network (e.g., LAN, WAN, or the Internet).

DoD has mandated the use of the Common Access Card (CAC) token/credential to support identity management and personal authentication for systems covered under HSPD 12. DoD recommended architecture for network devices is for system administrators to authenticate using an authentication server using the DoD CAC credential with DoD-approved PKI.

This requirement also applies to the account of last resort and the root account only if non-local access via the network is enabled for these accounts (not recommended).

This control does not apply to the account of last resort or root account. DoD prohibits local user accounts on the device, except for an account of last resort and (where applicable) a root account.'
  desc 'check', 'Multifactor authentication is managed through the LDAP server. Verify that LDAP (remote authentication) is enabled.

Navigate to Settings >> Initial Configuration >> Authentication.

Verify that LDAP server information is correctly entered and enabled.

Verify that "Native takes precedence" is disabled.

If LDAP server is not connected, or if "Native takes precedence" is not disabled, this is a finding.'
  desc 'fix', 'Configure the LDAP server to be connected correctly and disable "Native takes precedence".

Navigate to Settings >> Initial Configuration >> Authentication.

Enter the correct LDAP server information and press the "Enable" button.

Press the "Native takes precedence" "Disable" button (if it is not already disabled).'
  impact 0.5
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-76579r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76953'
  tag rid: 'SV-91649r1_rule'
  tag stig_id: 'DBNW-DM-000050'
  tag gtitle: 'SRG-APP-000149-NDM-000247'
  tag fix_id: 'F-83649r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000765']
  tag nist: ['IA-2 (1)']
end
