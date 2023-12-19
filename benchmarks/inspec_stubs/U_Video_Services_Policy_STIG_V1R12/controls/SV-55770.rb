control 'SV-55770' do
  title 'An ISDN-based VTC system supporting secure (classified) and non-secure (unclassified) conferences must utilize an approved pair of EIA-530 A/B switches operated in tandem or a dual A/B switch to switch the Type 1 encryptor in/out of the circuit between the CODEC and IMUX.'
  desc 'ISDN-based VTC systems supporting secure (classified) and non-secure (unclassified) conferences operate in an unclassified manner while connecting a call. If the call is to be classified or “secure” at any level, the Type 1 encryptor is switched into the circuit between the CODEC and IMUX, then synced with the other end before the conference discussions can “go secure”. This is typically performed using approved A/B switches on both sides of the encryptor operated in tandem. 
The use of the word “tandem” here does not refer to public switched telephone network (PSTN) tandem switches. This refers to a pair of A/B switches that are operated at the same time.'
  desc 'check', 'Review the documentation to determine whether approved A/B switches are in place. DISN Video Services (DVS) maintains a list of A/B switches and dial isolators that have been TEMPEST certified to meet the above requirements at http://disa.mil/Services/Network-Services/Video/~/media/Files/DISA/Services/DVS/red_black_peripherals.xls. If A/B switches operated in tandem or a dual A/B switch is not implemented and used, or the A/B switches are not on the list, this is a finding.'
  desc 'fix', 'Obtain and install approved EIA-530 A/B switches.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-49190r6_chk'
  tag severity: 'medium'
  tag gid: 'V-43041'
  tag rid: 'SV-55770r1_rule'
  tag stig_id: 'RTS-VTC 7360'
  tag gtitle: 'RTS-VTC 7360 [ISDN]'
  tag fix_id: 'F-48621r3_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
