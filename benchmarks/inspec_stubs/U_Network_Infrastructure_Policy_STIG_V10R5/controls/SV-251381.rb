control 'SV-251381' do
  title 'Command and Control (C2) and non-C2 exceptions of SIPRNet must be documented in the enclaves accreditation package and an Authority to Connect (ATC) or Interim ATC  amending the connection approval received prior to implementation.'
  desc "Any exception to use SIPRNet must be documented in an update to the enclave's accreditation package and an Authority to Connect (ATC) or Interim ATC  amending the connection approval received prior to implementation."
  desc 'check', 'Review SIPRNet accreditation package and an Interim Authority to Connect/Authority to Connect (IATC/ATC) amending the connection approval received.

If C2 and non-C2 exceptions are not documented, this is a finding.'
  desc 'fix', 'Document all SIPRNet connections.'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-54816r806096_chk'
  tag severity: 'medium'
  tag gid: 'V-251381'
  tag rid: 'SV-251381r806098_rule'
  tag stig_id: 'NET1827'
  tag gtitle: 'NET1827'
  tag fix_id: 'F-54769r806097_fix'
  tag 'documentable'
  tag legacy: ['V-14742', 'SV-15498']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
