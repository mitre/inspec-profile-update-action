control 'SV-23718' do
  title 'The Fire and Emergency Services (FES) communications over a sites private telephone system  must provide the originating telephone number to the emergency services answering point or call center through a transfer of Automatic Number Identification (ANI) or Automatic Location Identification (ALI) information.'
  desc 'The implementation of Enhanced F&ES telecommunications services requires that the emergency services answering point or call center be able to automatically locate the calling party in the event they are unable provide their location themselves. This is a two part process. First the telephone system must be able to provide the answering station with the telephone number from which the emergency call originated. This is Automatic Number Identification (ANI) information. The second step in the process is that this phone number must be correlated to a physical address or location. This is called Automatic Location Identification (ALI) information. ANI information comes from the telephone system controller. ALI information may come from an external database that associates the ANI information to the ALI information or the telephone system controller may maintain the ALI database internally. If the ALI database is internal to the telephone system controller, emergency services answering point or call center only needs to receive ALI information providing it contains the originating telephone number.

For enterprise systems, the support for E911 by the enterprise LSC (or any remote LSC construct) is governed by FCC rules, as well as other federal, state, and local law. The design and implementation of all telephone system systems must include reasonable efforts to provide E911, even when the access connection to the Enterprise LSC is severed.'
  desc 'check', 'Interview the ISSO to validate compliance with the following requirement: 
Inspect the telephone system configuration to determine compliance with the requirement. Verity the local DoD telephone system, VoIP or traditional, is configured to provide the originating telephone number of an F&ES call to the emergency services answering point or call center through a transfer of Automatic Number Identification (ANI) or Automatic Location Identification (ALI) information. 

If the originating telephone number of an F&ES call is not available or is not provided to the emergency services answering point or call center, this is a finding.'
  desc 'fix', 'Configure the local DoD telephone system, VoIP or traditional, to provide the originating telephone number of an F&ES call to the emergency services answering point or call center through a transfer of Automatic Number Identification (ANI) or Automatic Location Identification (ALI) information.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-25745r4_chk'
  tag severity: 'medium'
  tag gid: 'V-21509'
  tag rid: 'SV-23718r3_rule'
  tag stig_id: 'VVT 2010'
  tag gtitle: 'VVT 2010'
  tag fix_id: 'F-22298r3_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Information Assurance Manager', 'Other']
end
