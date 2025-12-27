control 'SV-23456' do
  title 'Voice Video Services Policy guidance being utilized must be supported by DISA.'
  desc 'Security flaws with software applications are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant software updates (e.g., patches, service packs, and hot fixes). Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously.

Organization-defined time periods for updating security-relevant software may vary based on a variety of factors including, for example, the security category of the information system or the criticality of the update (i.e., severity of the vulnerability related to the discovered flaw).

The current Voice Video STIG Guidance will be sunset because technology advancements and best practices have outpaced the existing guidelines. DISA recognizes the current VOIP STIGs require updating and will be placing the VOIP guidance on the STIG sunset list until new VOIP guidance can be developed. Plans are currently underway to draft new guidance, in the interim period, the sunset VOIP guidance can be utilized to the extent possible, but it will not be updated.'
  desc 'check', 'The Voice Video Services Policy STIG is no longer updated by DISA.

If the STIG is being utilized without utilizing current vendor best practices, this is a finding.'
  desc 'fix', 'Utilize vendor best practices and the sunset Voice Video Services Policy guidance to the extent possible.'
  impact 0.7
  ref 'DPMS Target VVoiP Device'
  tag check_id: 'C-25776r2_chk'
  tag severity: 'high'
  tag gid: 'V-22222'
  tag rid: 'SV-23456r3_rule'
  tag stig_id: 'VVoIP 9000'
  tag gtitle: 'VVT 9000'
  tag fix_id: 'F-22311r2_fix'
  tag 'documentable'
end
