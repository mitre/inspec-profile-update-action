control 'SV-104241' do
  title 'Symantec ProxySG providing user authentication intermediary services must implement multifactor authentication for remote access to privileged accounts such that one of the factors is provided by a device separate from the system gaining access.'
  desc 'For remote access to privileged accounts, the purpose of requiring a device that is separate from the information system gaining access for one of the factors during multifactor authentication is to reduce the likelihood of compromising authentication credentials stored on the system.

Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. Government Personal Identity Verification card and the DoD common access card.

A privileged account is defined as an information system account with authorizations of a privileged user.

Remote access is access to DoD-nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

NOTE: If authentication with client side verification is enabled, it may cause an increase in traffic to the console session and communications lag to the management console. The vendor states this is a known issue which will not likely get resolved until the entire interface has been migrated over to HTML5. Contact vendor for support.'
  desc 'check', 'Multiple methods of multifactor authentication are supported. Verify that an approved method is configured (such as CAC certificate authentication).

1. Log on to the Web Management Console.
2. Browse to Configuration >> Authentication.
3. Click each of the above authentication mechanisms and Verify that at least one approved multifactor authentication method is configured.

If Symantec ProxySG providing user authentication intermediary services does not implement multifactor authentication for remote access to privileged accounts such that one of the factors is provided by a device separate from the system gaining access, this is a finding.'
  desc 'fix', 'Configure an approved method of multifactor authentication (such as CAC certificate authentication).

1. Log on to the Web Management Console.
2. Browse to Configuration >> Authentication.
3. Configure at least one multifactor method (such as CAC certificate authentication) per the ProxySG Administration Guide (CAC Certificate authentication configuration is covered in Chapter 52: Certificate Realm Authentication and Chapter 58: LDAP Realm Authentication).'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93473r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94287'
  tag rid: 'SV-104241r2_rule'
  tag stig_id: 'SYMP-AG-000360'
  tag gtitle: 'SRG-NET-000340-ALG-000091'
  tag fix_id: 'F-100403r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001948']
  tag nist: ['IA-2 (11)']
end
