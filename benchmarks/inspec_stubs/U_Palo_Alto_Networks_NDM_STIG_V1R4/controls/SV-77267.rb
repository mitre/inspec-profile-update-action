control 'SV-77267' do
  title 'The Palo Alto Networks security platform must use DoD-approved PKI rather than proprietary or self-signed device certificates.'
  desc 'DoD Instruction 8520.02, Public Key Infrastructure (PKI) and Public Key (PK) Enabling mandates that certificates must be issued by the DoD PKI or by a DoD-approved PKI for authentication, digital signature, or encryption.'
  desc 'check', 'Go to Device >> Certificate Management >> Certificates
Installed Certificates are listed in the "Device Certificates" tab.
If any of the have the name or identifier of a non-approved source in the "Issuer" field, this is a finding.'
  desc 'fix', 'Obtain a Device Certificate from the DoD PKI or from a DoD-approved PKI:
Go to Device >> Certificate Management >> Certificates
Select "Import" (at the bottom of the pane). 
In the "Import Certificate" pane, complete each field.
Select "OK".'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks Security Platform NDM'
  tag check_id: 'C-63585r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62777'
  tag rid: 'SV-77267r1_rule'
  tag stig_id: 'PANW-NM-000141'
  tag gtitle: 'SRG-APP-000516-NDM-000344'
  tag fix_id: 'F-68697r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001159']
  tag nist: ['CM-6 b', 'SC-17 a']
end
