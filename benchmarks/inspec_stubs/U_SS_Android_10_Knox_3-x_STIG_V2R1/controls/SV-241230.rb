control 'SV-241230' do
  title 'Samsung Android Work Environment must be configured to enable Certificate Revocation checking.'
  desc 'A Certificate Revocation List (CRL) allows a certificate issuer to revoke a certificate for any reason, including improperly issued certificates and compromise of the private keys. Checking the revocation status of the certificate mitigates the risk associated with using a compromised certificate.

Online Certificate Status Protocol (OCSP) is a protocol for obtaining the revocation status of a certificate. It addresses problems associated with using CRLs. When OCSP is enabled, it is used prior to CRL checking. If OCSP could not obtain a decisive response about a certificate, it will then try to use CRL checking. The OCSP response server must be listed in the certificate information under Authority Info Access.

This feature must be enabled for a Samsung Android device to be in the NIAP-certified CC Mode of operation.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Samsung Android Work Environment configuration settings to determine if Certificate Revocation checking is enabled.

Confirm if Method #1 or #2 is used at the Samsung device site and follow the appropriate procedure.

This validation procedure is performed on the management tool Administration Console only.

****

Method #1: CRL checking

On the management tool, in the Work profile KPE certificate section, verify that "Revocation check" is set to "enable for all apps".

If on the management tool "Revocation check" is not set to "enable for all apps", this is a finding.

****

Method #2: OCSP with CRL fallback

On the management tool, do the following:
1. In the Work profile KPE certificate section, verify that "Revocation check" is set to "enable for all apps".
2. In the Work profile KPE restrictions section, verify that "OCSP check" is set to "enable for all apps".

If on the management tool "Revocation check" is not set to "enable for all apps" or if "OCSP check" is not set to "enable for all apps", this is a finding.'
  desc 'fix', 'Configure Samsung Android Work Environment to enable Certificate Revocation checking.

Do one of the following:
- Method #1: CRL checking
- Method #2: OCSP with CRL fallback

****

Method #1: CRL checking

On the management tool, in the Work profile KPE certificate section, set "Revocation check" to "enable for all apps".

Refer to the management tool documentation to determine how to configure Revocation checking to "enable for all apps". Some may, for example, allow a wildcard string: "*".

****

Method #2: OCSP with CRL fallback

On the management tool, do the following:
1. In the Work profile KPE certificate section, set "Revocation check" to "enable for all apps".
2. In the Work profile KPE restrictions section, set "OCSP check" to "enable for all apps".

Refer to the management tool documentation to determine how to configure Revocation and OCSP checking to "enable for all apps". Some may, for example, allow a wildcard string: "*".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 10 with Knox 3-x'
  tag check_id: 'C-44506r680329_chk'
  tag severity: 'medium'
  tag gid: 'V-241230'
  tag rid: 'SV-241230r680331_rule'
  tag stig_id: 'KNOX-10-012000'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-44465r680330_fix'
  tag 'documentable'
  tag legacy: ['SV-109093', 'V-99989']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
