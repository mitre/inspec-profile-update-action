control 'SV-252952' do
  title 'TOSS must use multifactor authentication for network and local access to privileged and non-privileged accounts.'
  desc 'Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased.

Multifactor authentication requires using two or more factors to achieve authentication.

Factors include: 
1) something a user knows (e.g., password/PIN);
2) something a user has (e.g., cryptographic identification device, token); and
3) something a user is (e.g., biometric).

A privileged account is defined as an information system account with authorizations of a privileged user.

Network access is defined as access to an information system by a user (or a process acting on behalf of a user) communicating through a network (e.g., local area network, wide area network, or the Internet).

The DoD CAC with DoD-approved PKI is an example of multifactor authentication.

'
  desc 'check', 'Verify the operating system uses multifactor authentication for network access to privileged accounts. If it does not, this is a finding.

Note: This requirement is applicable to any externally accessible nodes of the TOSS system. For compute or other intra-cluster only accessible nodes, this requirement is Not Applicable.

One possible method for meeting this requirement is to require smart card logon for access to interactive accounts.

Check that the "pam_cert_auth" setting is set to "true" in the "/etc/sssd/sssd.conf" file.

Check that the "try_cert_auth" or "require_cert_auth" options are configured in both "/etc/pam.d/system-auth" and "/etc/pam.d/smartcard-auth" files with the following command:

$ sudo grep cert_auth /etc/sssd/sssd.conf /etc/pam.d/*

/etc/sssd/sssd.conf:pam_cert_auth = True
/etc/pam.d/smartcard-auth:auth sufficient pam_sss.so try_cert_auth
/etc/pam.d/system-auth:auth [success=done authinfo_unavail=ignore ignore=ignore default=die] pam_sss.so try_cert_auth

If "pam_cert_auth" is not set to "true" in "/etc/sssd/sssd.conf", this is a finding.

If "pam_sss.so" is not set to "try_cert_auth" or "require_cert_auth" in both the "/etc/pam.d/smartcard-auth" and "/etc/pam.d/system-auth" files, this is a finding.'
  desc 'fix', 'Configure the operating system to use multifactor authentication for network access to privileged accounts.

One possible method for meeting this requirement is to require smart card logon for access to interactive accounts; in which case, configure TOSS to use multifactor authentication for local access to accounts.

Add or update the "pam_cert_auth" setting in the "/etc/sssd/sssd.conf" file to match the following line:

[pam]
pam_cert_auth = True

Add or update "pam_sss.so" with "try_cert_auth" or "require_cert_auth" in the "/etc/pam.d/system-auth" and "/etc/pam.d/smartcard-auth" files based on the following examples:

/etc/pam.d/smartcard-auth:auth sufficient pam_sss.so try_cert_auth

/etc/pam.d/system-auth:auth [success=done authinfo_unavail=ignore ignore=ignore default=die] pam_sss.so try_cert_auth

The "sssd" service must be restarted for the changes to take effect. To restart the "sssd" service, run the following command:

$ sudo systemctl restart sssd.service'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56405r824178_chk'
  tag severity: 'medium'
  tag gid: 'V-252952'
  tag rid: 'SV-252952r824180_rule'
  tag stig_id: 'TOSS-04-020070'
  tag gtitle: 'SRG-OS-000105-GPOS-00052'
  tag fix_id: 'F-56355r824179_fix'
  tag satisfies: ['SRG-OS-000105-GPOS-00052', 'SRG-OS-000106-GPOS-00053', 'SRG-OS-000107-GPOS-00054', 'SRG-OS-000108-GPOS-00055']
  tag 'documentable'
  tag cci: ['CCI-000765', 'CCI-000766', 'CCI-000767', 'CCI-000768']
  tag nist: ['IA-2 (1)', 'IA-2 (2)', 'IA-2 (3)', 'IA-2 (4)']
end
