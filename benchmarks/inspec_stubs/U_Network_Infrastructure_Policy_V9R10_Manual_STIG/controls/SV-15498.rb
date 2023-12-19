control 'SV-15498' do
  title 'Command and Control (C2) and non-C2 exceptions of SIPRNet must be documented in the enclaves accreditation package and an Authority to Connect (ATC) or Interim ATC  amending the connection approval received prior to implementation.'
  desc 'Any exception to use SIPRNet must be documented in an update to the enclave’s accreditation package and an Authority to Connect (ATC) or Interim ATC  amending the connection approval received prior to implementation.'
  desc 'check', 'Review SIPRNet accreditation package and an Interim Authority to Connect/Authority to Connect (IATC/ATC) amending the connection approval received.

If C2 and non-C2 exceptions are not documented, this is a finding.'
  desc 'fix', 'Document all SIPRNet connections.'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-12964r2_chk'
  tag severity: 'medium'
  tag gid: 'V-14742'
  tag rid: 'SV-15498r2_rule'
  tag stig_id: 'NET1827'
  tag gtitle: 'SIPRNet exceptions must be documented'
  tag fix_id: 'F-14208r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
