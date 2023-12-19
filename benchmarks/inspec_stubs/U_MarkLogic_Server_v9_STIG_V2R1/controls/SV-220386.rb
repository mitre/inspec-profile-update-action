control 'SV-220386' do
  title 'MarkLogic Server must only accept end-entity certificates issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs) for the establishment of all encrypted sessions.'
  desc 'Only DoD-approved external PKIs have been evaluated to ensure that they have security controls and identity vetting procedures in place sufficient for DoD systems to rely on the identity asserted in the certificate. PKIs lacking sufficient security controls and identity vetting procedures risk being compromised and issuing certificates that enable adversaries to impersonate legitimate users. 

The authoritative list of DoD-approved PKIs is published at https://public.cyber.mil/pki-pke/interoperability/.

This requirement focuses on communications protection for the DBMS session rather than for the network packet.'
  desc 'check', 'Review MarkLogic settings to determine whether the server will accept non-DoD approved PKI end-entity certificates, this is a finding.

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Security icon.
2. Click the Certificate Authorities icon.
3. If there are any PKI end-entity certificates that are not DoD approved, this is a finding.'
  desc 'fix', 'Configure MarkLogic to accept only DoD and DoD-approved PKI end-entity certificates by revoking trust in any certificates not issued by a DoD-approved certificate authority.

Perform the fix from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Security icon.
2. Click the Certificate Authorities icon.
3. Remove all PKI end-entity certificates not approved by DoD.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22101r401609_chk'
  tag severity: 'medium'
  tag gid: 'V-220386'
  tag rid: 'SV-220386r855491_rule'
  tag stig_id: 'ML09-00-008400'
  tag gtitle: 'SRG-APP-000427-DB-000385'
  tag fix_id: 'F-22090r401610_fix'
  tag 'documentable'
  tag legacy: ['SV-110121', 'V-101017']
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
