control 'SV-223647' do
  title 'Expired digital certificates must not be used.'
  desc 'The longer and more often a key is used, the more susceptible it is to loss or discovery. This weakens the assurance provided to a relying Party that the unique binding between a key and its named subscriber is valid. Therefore, it is important that certificates are periodically refreshed. This is in accordance with DoD requirement. Expired Certificate must not be in use.'
  desc 'check', 'From the ISPF Command Shell enter:
RACDCERT CERTAUTH LIST

If no certificate information is found, this is not a finding.

NOTE: Certificates are only valid when their Status is TRUST. Therefore, you may ignore certificates with the NOTRUST status during the following check.

Check the expiration (End Date) for each certificate with a status of TRUST.

If the expiration date has passed, this is a finding.'
  desc 'fix', 'If the certificate is a user or device certificate with a status of TRUST, follow procedures to obtain a new certificate or re-key certificate. If it is an expired CA certificate remove it.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25320r621704_chk'
  tag severity: 'medium'
  tag gid: 'V-223647'
  tag rid: 'SV-223647r604139_rule'
  tag stig_id: 'RACF-CE-000020'
  tag gtitle: 'SRG-OS-000066-GPOS-00034'
  tag fix_id: 'F-25308r514631_fix'
  tag 'documentable'
  tag legacy: ['V-97999', 'SV-107103']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
