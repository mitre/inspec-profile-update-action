control 'SV-227951' do
  title 'Any NIS+ server must be operating at security level 2.'
  desc 'If the NIS+ server is not operating in, at least, security level 2, there is no encryption and the system could be penetrated by intruders and/or malicious users.'
  desc 'check', 'If the system is not using NIS+, this is not applicable.

Check the system to determine if NIS+ security level 2 is implemented.

Procedure:
# niscat cred.org_dir 

If the second column does not contain DES, the system is not using NIS+ security level 2, and this is a finding.'
  desc 'fix', 'Ensure the NIS+ server is operating at security level 2 by editing /usr/lib/nis/nisserver and ensuring the line containing SEC= is set to the numeral 2, for example:
 
SEC=2                   # 2=DES or 3=RSA

Security Level 0 is designed for testing and initial setup of the NIS+ namespace.  When running at level 0, the daemon does not enforce access control.  Any client is allowed to perform any operation, including updates and deletions.

Security level 1 accepts AUTH_SYS and AUTH_DES credentials for authenticating clients and authorizing them to perform NIS+ operations.  This is not a secure mode of operation since AUTH_SYS credentials are easily forged.  It should not be used on networks in which any untrusted user may potentially have access.  Security level 2 accepts only AUTH_DES credentials for authentication and authorization.  This is the highest level of security currently provided by the NIS+ service and the default security level if the -S option is not used.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-36482r603049_chk'
  tag severity: 'medium'
  tag gid: 'V-227951'
  tag rid: 'SV-227951r603266_rule'
  tag stig_id: 'GEN006460'
  tag gtitle: 'SRG-OS-000510'
  tag fix_id: 'F-36446r603050_fix'
  tag 'documentable'
  tag legacy: ['V-926', 'SV-28453']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
